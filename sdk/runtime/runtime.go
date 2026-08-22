package runtime

import (
	"context"
	"fmt"
	"io"

	"github.com/open-asm/oasm-connectors/sdk/connector"
	"github.com/open-asm/oasm-connectors/sdk/env"
	"github.com/open-asm/oasm-connectors/sdk/logging"
	pb "github.com/open-asm/oasm-connectors/sdk/proto/gen"
	"github.com/open-asm/oasm-connectors/sdk/transport"
)

// Runtime owns a Connector and runs until the context is cancelled.
type Runtime struct {
	conn   *connector.Connector
	logger *logging.Logger
}

// New creates a Runtime for the given Connector.
func New(c *connector.Connector) *Runtime {
	return &Runtime{
		conn:   c,
		logger: logging.New("runtime"),
	}
}

// Run connects to the Worker gRPC server using env-injected config,
// registers, and enters the execute loop. Falls back to blocking on
// ctx.Done() when WORKER_GRPC_ADDR is not set (legacy mode).
func (r *Runtime) Run(ctx context.Context) error {
	cfg, err := env.Load()
	if err != nil {
		// No Worker config — legacy mode, just block
		r.logger.Info("no WORKER_GRPC_ADDR set, blocking on context")
		<-ctx.Done()
		return ctx.Err()
	}

	inputs := env.LoadInputs()
	r.logger.Infof("loaded %d env inputs", len(inputs))

	// Dial Worker
	conn, err := transport.Connect(ctx, cfg.WorkerAddr)
	if err != nil {
		return fmt.Errorf("dial worker: %w", err)
	}
	defer conn.Close()

	client := pb.NewConnectorServiceClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("open connect stream: %w", err)
	}

	// Register
	if err := stream.Send(&pb.ConnectorMessage{
		Message: &pb.ConnectorMessage_Register{
			Register: &pb.Register{Token: cfg.Token},
		},
	}); err != nil {
		return fmt.Errorf("send register: %w", err)
	}

	// Wait for RegisterAck
	ackMsg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("wait register ack: %w", err)
	}
	ack := ackMsg.GetRegisterAck()
	if ack == nil || !ack.Accepted {
		reason := "unknown"
		if ack != nil {
			reason = ack.Reason
		}
		return fmt.Errorf("registration rejected: %s", reason)
	}
	r.logger.Info("registered with worker")

	// Execute loop
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}

		switch m := msg.Message.(type) {
		case *pb.WorkerMessage_Execute:
			if err := r.handleExecute(ctx, stream, m.Execute, inputs); err != nil {
				return err
			}

		case *pb.WorkerMessage_Cancel:
			r.logger.Infof("cancel execution_id=%s", m.Cancel.ExecutionId)
			// Best-effort: context cancellation propagates when stream closes
		}
	}
}

// handleExecute runs the adapter for a single ExecuteJob and streams
// results back. All stream sends happen in this goroutine to avoid
// concurrent write races on the gRPC stream.
func (r *Runtime) handleExecute(ctx context.Context, stream pb.ConnectorService_ConnectClient, exec *pb.ExecuteJob, envInputs map[string]any) error {
	r.logger.Infof("execute job_id=%s tool=%s exec_id=%s", exec.JobId, exec.Tool, exec.ExecutionId)

	// Merge inputs: env defaults, Worker-provided override
	inputs := make(map[string]any, len(envInputs)+len(exec.Inputs))
	for k, v := range envInputs {
		inputs[k] = v
	}
	for k, v := range exec.Inputs {
		inputs[k] = v
	}

	out := make(chan []byte, 16)
	errCh := make(chan error, 1)

	go func() {
		errCh <- r.conn.Execute(ctx, inputs, out)
		close(out)
	}()

	// Stream results — single goroutine, safe for non-concurrent stream writes
	for data := range out {
		if err := stream.Send(&pb.ConnectorMessage{
			Message: &pb.ConnectorMessage_Result{
				Result: &pb.Result{
					ExecutionId: exec.ExecutionId,
					Data:        data,
				},
			},
		}); err != nil {
			return fmt.Errorf("send result: %w", err)
		}
	}

	adapterErr := <-errCh

	// Send Done
	doneMsg := &pb.Done{ExecutionId: exec.ExecutionId}
	if adapterErr != nil {
		doneMsg.Error = adapterErr.Error()
		r.logger.Errorf("adapter error: %v", adapterErr)
	}
	if err := stream.Send(&pb.ConnectorMessage{
		Message: &pb.ConnectorMessage_Done{Done: doneMsg},
	}); err != nil {
		return fmt.Errorf("send done: %w", err)
	}

	return nil
}
