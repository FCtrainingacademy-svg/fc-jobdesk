# FC JobDesk

Leads in, offered to 2–3 engineers, first to accept gets the job, then materials for K's Plumbing Store.

## How it works
1. **Lead in** – the office adds a lead, or a customer fills in the website form (`/lead-form`, embed it on fctrainingacademy.com).
2. **Engineers set availability** – each engineer signs in (username = their email, password they choose) and taps the mornings/afternoons they're free.
3. **Offer** – the office picks a day + slot; engineers who are free are pre-ticked. JobDesk emails each one an Accept link. The first to accept (by link or in the app) gets the job; the others' offers close. Offers expire after `OFFER_HOURS` and the job goes back to Leads.
4. **Booked** – the engineer gets the full address, the office gets a confirmation, and the customer (if they gave an email) gets their appointment.
5. **Materials** – the engineer builds a list (boiler make/model + fittings/pipes). "Order from K's Plumbing Store" switches on when `KS_ORDER_WEBHOOK_URL` is set.

## Safety details
- Offer links only show the postcode area until accepted. Accepting needs a button press (so email link-scanners can't accept by accident).
- Double booking is prevented with a database row lock.
- Passwords hashed with bcrypt; sessions are httpOnly cookies; API writes need a custom header (CSRF guard); login and form rate limits.

## Run locally
```
npm install
DATABASE_URL=postgres://... ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=longpassword BASE_URL=http://localhost:3000 node server.js
npm test   # with the server running on port 3999, see test/flow.test.js
```

## K's Plumbing Store order payload (for later)
`POST KS_ORDER_WEBHOOK_URL` with header `X-JobDesk-Key: KS_ORDER_KEY`:
```json
{ "source":"fc-jobdesk","job_ref":"FC-1001","deliver_day":"2026-09-29","slot":"am","postcode":"IG1 2AB","address":"...",
  "engineer":{"name":"...","email":"...","phone":"..."},"boiler":"Vaillant ecoTEC plus 832",
  "lines":[{"item":"Magnetic system filter","qty":1}],"notes":"Collect 8am" }
```
