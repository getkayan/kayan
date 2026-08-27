package gormstore

import (
	"fmt"
	"strings"

	scim "github.com/getkayan/kayan/kayan-scim"
	"gorm.io/gorm"
)

// applyFilter compiles a parsed SCIM filter into a GORM query.
//
// The filter arrives as an AST rather than as text, so this walks a tree
// instead of parsing. Every value is bound as a parameter — the column name is
// resolved through the mapper and never interpolated, so a filter cannot reach
// the SQL grammar.
func applyFilter(db *gorm.DB, expr scim.FilterExpr, columnFor func(scim.Path) (string, error)) (*gorm.DB, error) {
	clause, args, err := buildClause(expr, columnFor)
	if err != nil {
		return nil, err
	}
	if clause == "" {
		return db, nil
	}
	return db.Where(clause, args...), nil
}

// buildClause renders one expression to a SQL fragment and its arguments.
func buildClause(expr scim.FilterExpr, columnFor func(scim.Path) (string, error)) (string, []any, error) {
	switch e := expr.(type) {
	case scim.ValuePath:
		return "", nil, fmt.Errorf("%w: value-path filters require a multi-valued storage mapping", scim.ErrFilterUnsupported)

	case scim.Comparison:
		return comparisonClause(e, columnFor)

	case scim.And:
		left, leftArgs, err := buildClause(e.Left, columnFor)
		if err != nil {
			return "", nil, err
		}
		right, rightArgs, err := buildClause(e.Right, columnFor)
		if err != nil {
			return "", nil, err
		}
		return "(" + left + " AND " + right + ")", append(leftArgs, rightArgs...), nil

	case scim.Or:
		left, leftArgs, err := buildClause(e.Left, columnFor)
		if err != nil {
			return "", nil, err
		}
		right, rightArgs, err := buildClause(e.Right, columnFor)
		if err != nil {
			return "", nil, err
		}
		return "(" + left + " OR " + right + ")", append(leftArgs, rightArgs...), nil

	case scim.Not:
		inner, args, err := buildClause(e.Expr, columnFor)
		if err != nil {
			return "", nil, err
		}
		return "NOT (" + inner + ")", args, nil

	default:
		return "", nil, scim.NewError("400", "invalidFilter",
			fmt.Sprintf("unsupported filter expression %T", expr))
	}
}

func comparisonClause(c scim.Comparison, columnFor func(scim.Path) (string, error)) (string, []any, error) {
	// A value filter selects within a multi-valued attribute, which a
	// relational adapter cannot express against a scalar column.
	if c.Path.Filter != nil {
		return "", nil, scim.NewError("400", "invalidFilter",
			"value filters are not supported by this storage implementation")
	}

	column, err := columnFor(c.Path)
	if err != nil {
		return "", nil, err
	}

	// The column comes from the mapper, never from the request, so quoting it
	// is safe. Values are always bound.
	quoted := quoteIdentifier(column)

	switch c.Operator {
	case scim.OpPresent:
		return fmt.Sprintf("(%s IS NOT NULL AND %s <> '')", quoted, quoted), nil, nil

	case scim.OpEqual:
		return quoted + " = ?", []any{c.Value}, nil

	case scim.OpNotEqual:
		return quoted + " <> ?", []any{c.Value}, nil

	case scim.OpContains:
		return quoted + " LIKE ?", []any{"%" + likeEscape(c.Value) + "%"}, nil

	case scim.OpStartsWith:
		return quoted + " LIKE ?", []any{likeEscape(c.Value) + "%"}, nil

	case scim.OpEndsWith:
		return quoted + " LIKE ?", []any{"%" + likeEscape(c.Value)}, nil

	case scim.OpGreaterThan:
		return quoted + " > ?", []any{c.Value}, nil

	case scim.OpGreaterThanOrEqual:
		return quoted + " >= ?", []any{c.Value}, nil

	case scim.OpLessThan:
		return quoted + " < ?", []any{c.Value}, nil

	case scim.OpLessThanOrEqual:
		return quoted + " <= ?", []any{c.Value}, nil

	default:
		return "", nil, scim.NewError("400", "invalidFilter",
			fmt.Sprintf("unsupported operator %q", c.Operator))
	}
}

// likeEscape neutralizes LIKE wildcards in a user-supplied value.
//
// Without it, a filter such as `userName co "%"` matches every row, turning a
// narrowing filter into a full listing.
func likeEscape(value any) string {
	s := fmt.Sprintf("%v", value)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// quoteIdentifier wraps a column name in double quotes, doubling any it
// contains.
//
// Column names come from the mapper rather than from the request, so this is
// belt and braces against a future path that forgets that.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
