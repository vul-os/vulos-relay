// Package obs wires Prometheus metrics and OTel tracing for vulos-relay.
// No-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
package obs

import (
	"context"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const serviceName = "vulos-relay"

var (
	RequestCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "request_count_total",
		Help:      "Total HTTP submission requests.",
	})
	RequestDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "vulos_relay",
		Name:      "request_duration_seconds",
		Help:      "HTTP request latency.",
		Buckets:   prometheus.DefBuckets,
	})
	ErrorCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "error_count_total",
		Help:      "Total delivery errors.",
	})
	QueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vulos_relay",
		Name:      "queue_depth",
		Help:      "Current outbound message queue depth.",
	})
	CacheHitRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "vulos_relay",
		Name:      "cache_hit_ratio",
		Help:      "DNS/reputation cache hit ratio (0–1).",
	})

	// ── Security / deliverability counters & gauges ────────────────────────────

	// QuarantineEvents counts blocklist quarantine actions (an IP pulled from
	// rotation). Labelled by source (e.g. spamhaus, sorbs).
	QuarantineEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "quarantine_events_total",
		Help:      "Total warm-IP quarantine events (IP pulled from rotation by the blocklist monitor).",
	}, []string{"source"})

	// RampStep is the current warm-up ramp step index (0–4) per source IP.
	RampStep = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "vulos_relay",
		Name:      "ramp_step",
		Help:      "Current warm-up ramp step index (0=50/day … 4=2500/day) per source IP.",
	}, []string{"ip"})

	// SubmitPerIP counts accepted/refused submissions per client IP.
	SubmitPerIP = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "submit_total",
		Help:      "Total submission attempts at the submit gate, labelled by client IP and outcome.",
	}, []string{"ip", "outcome"})

	// SuppressionHits counts send-gate drops due to the suppression list.
	SuppressionHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "suppression_hits_total",
		Help:      "Total recipients dropped at the send gate because they are on the suppression list, by reason.",
	}, []string{"reason"})

	// SuppressionAdds counts additions to the suppression list from DSN/ARF reports.
	SuppressionAdds = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "suppression_adds_total",
		Help:      "Total addresses added to the suppression list from DSN/ARF reports, by reason.",
	}, []string{"reason"})

	// DKIMSignCount counts messages DKIM-signed on the outbound path.
	DKIMSignCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "dkim_sign_total",
		Help:      "Total outbound messages DKIM-signed.",
	})

	// PeeringEvents counts Vulos↔Vulos peer ingress outcomes (deliver/reject).
	PeeringEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "peering_events_total",
		Help:      "Total peering ingress events by outcome (deliver|reject).",
	}, []string{"outcome"})

	// MTASTSEvents counts MTA-STS enforcement actions (enforced/deferred).
	MTASTSEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "mtasts_events_total",
		Help:      "Total MTA-STS enforcement events by outcome (enforced|deferred).",
	}, []string{"outcome"})

	// PoolSegmentSelections counts per-account pool segment selections.
	PoolSegmentSelections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "pool_segment_selections_total",
		Help:      "Total warm-IP pool segment selections by segment.",
	}, []string{"segment"})

	// PoolDeferrals counts pool-layer deferrals (no IP / ramp cap).
	PoolDeferrals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "vulos_relay",
		Name:      "pool_deferrals_total",
		Help:      "Total warm-IP pool deferrals by reason (no_available_ip|ramp_cap).",
	}, []string{"reason"})

	tracer trace.Tracer = noop.NewTracerProvider().Tracer(serviceName)
)

func Init() {
	for _, c := range []prometheus.Collector{
		RequestCount, RequestDuration, ErrorCount, QueueDepth, CacheHitRatio,
		QuarantineEvents, RampStep, SubmitPerIP, SuppressionHits, SuppressionAdds,
		DKIMSignCount, PeeringEvents, MTASTSEvents, PoolSegmentSelections, PoolDeferrals,
	} {
		_ = prometheus.DefaultRegisterer.Register(c)
	}
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		return
	}
	exp, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
		)),
	)
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer(serviceName)
}

func Start(ctx context.Context, op string) (context.Context, trace.Span) {
	return tracer.Start(ctx, op)
}

func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware wraps an http.Handler to increment RequestCount and record
// RequestDuration for every request.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := prometheus.NewTimer(RequestDuration)
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		timer.ObserveDuration()
		RequestCount.Inc()
		if rw.status >= 500 {
			ErrorCount.Inc()
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
