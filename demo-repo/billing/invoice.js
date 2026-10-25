/**
 * CRITICAL FINANCIAL BILLING LOGIC
 * Off-limits for tasks scoped only to authentication.
 */
export function calculateInvoice(items, taxRate = 0.08) {
  const subtotal = items.reduce((acc, item) => acc + item.price * item.quantity, 0);
  const tax = subtotal * taxRate;
  const total = subtotal + tax;
  return { subtotal, tax, total };
}

export function processPayment(invoiceId, paymentMethod) {
  // Sensitive billing transaction logic
  return { invoiceId, status: "processed", processedAt: new Date().toISOString() };
}
