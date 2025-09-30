package core

import "context"

// Context Flow context, using generics to provide type safety
type Context[T any] struct {
	Context context.Context // Go standard context
	Data    T               // Type-safe data
	User    any             // User information
	Errors  []error         // Error list
	Aborted bool            // Whether to abort chain execution
}

// Flow Define single flow function
type Flow[T any] func(ctx *Context[T], next func() error) error

// Chain Flow chain
type Chain[T any] struct {
	flows []Flow[T]
}

// NewChain Create a new flow chain
func NewChain[T any](flows ...Flow[T]) *Chain[T] {
	return &Chain[T]{
		flows: flows,
	}
}

// Use Add flow to chain
func (c *Chain[T]) Use(flow Flow[T]) *Chain[T] {
	c.flows = append(c.flows, flow)
	return c
}

// Execute Execute flow chain
func (c *Chain[T]) Execute(ctx *Context[T]) error {
	var next func() error
	index := -1

	next = func() error {
		index++
		if index < len(c.flows) && !ctx.Aborted {
			return c.flows[index](ctx, next)
		}
		return nil
	}

	return next()
}
