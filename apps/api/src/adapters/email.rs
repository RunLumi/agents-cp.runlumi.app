use crate::app::AppState;

/// Deliver a transactional authentication message when the Worker has the
/// Cloudflare Email Sending binding. Development intentionally no-ops so the
/// local vertical journey can use its explicitly marked fixture code.
pub async fn deliver_auth_code(
    state: &AppState,
    to: &str,
    code: &str,
    purpose: &str,
) -> worker::Result<()> {
    if state.environment == "development" {
        return Ok(());
    }
    let from = state
        .email_from
        .as_deref()
        .ok_or_else(|| worker::Error::RustError("email sender is not configured".into()))?;
    let binding = state
        .email
        .as_ref()
        .ok_or_else(|| worker::Error::RustError("email binding is not configured".into()))?;
    let subject = match purpose {
        "verification" => "Verify your Lumi Agents email",
        "login" => "Your Lumi Agents sign-in code",
        "invitation" => "You have a Lumi Agents invitation",
        _ => "Lumi Agents security notification",
    };
    let body = format!(
        "Your Lumi Agents {purpose} code is:\n\n{code}\n\nThis code is short-lived and can be used only once. If you did not request it, you can ignore this message."
    );
    let raw = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}"
    );
    let message = worker::EmailMessage::new(from, to, &raw)?;
    binding.send(&message).await?;
    Ok(())
}
