package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/stripe/stripe-go/v81"
	"github.com/stripe/stripe-go/v81/checkout/session"
	"github.com/stripe/stripe-go/v81/webhook"
)

func main() {
	// Set Stripe API key from environment
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
	if stripe.Key == "" {
		log.Fatal("STRIPE_SECRET_KEY not set")
	}

	http.HandleFunc("/api/stripe/checkout", corsMiddleware(handleCheckout))
	http.HandleFunc("/api/stripe/webhook", handleWebhook)
	http.HandleFunc("/api/stripe/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	port := os.Getenv("STRIPE_PORT")
	if port == "" {
		port = "8090"
	}

	log.Printf("Stripe checkout server starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

type CheckoutRequest struct {
	PriceID string `json:"priceId"`
	Email   string `json:"email,omitempty"`
}

func handleCheckout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CheckoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Default price ID if not provided
	priceID := req.PriceID
	if priceID == "" {
		priceID = "price_1SfR5gAzUYb98zLVVdE1TQ8H" // Default Pro Scanner price
	}

	// Create Stripe checkout session
	params := &stripe.CheckoutSessionParams{
		Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
		SuccessURL: stripe.String("https://theintel.report/success?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String("https://theintel.report/pricing"),
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			TrialPeriodDays: stripe.Int64(7), // 7-day free trial
		},
	}

	// Add customer email if provided
	if req.Email != "" {
		params.CustomerEmail = stripe.String(req.Email)
	}

	s, err := session.New(params)
	if err != nil {
		log.Printf("Stripe error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"sessionId": s.ID,
		"url":       s.URL,
	})
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading webhook body: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	endpointSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	event, err := webhook.ConstructEvent(payload, r.Header.Get("Stripe-Signature"), endpointSecret)
	if err != nil {
		log.Printf("Webhook signature verification failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Handle the event
	switch event.Type {
	case "checkout.session.completed":
		log.Printf("Checkout session completed: %s", event.ID)
		// TODO: Grant access to user
	case "customer.subscription.created":
		log.Printf("Subscription created: %s", event.ID)
	case "customer.subscription.deleted":
		log.Printf("Subscription cancelled: %s", event.ID)
		// TODO: Revoke access
	case "invoice.payment_failed":
		log.Printf("Payment failed: %s", event.ID)
		// TODO: Send warning email
	}

	w.WriteHeader(http.StatusOK)
}
