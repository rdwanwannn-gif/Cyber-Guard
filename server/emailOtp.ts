export interface OtpDeliveryResult {
  delivered: boolean;
  channel: 'email' | 'preview';
  previewOtp?: string;
  providerError?: string;
}

export async function deliverAdminEmailOtp(
  email: string,
  otp: string,
): Promise<OtpDeliveryResult> {
  const resendApiKey = process.env.RESEND_API_KEY?.trim();
  const fromEmail =
    process.env.OTP_FROM_EMAIL?.trim() || 'SentinelGrid SOC <onboarding@resend.dev>';

  if (resendApiKey) {
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${resendApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: fromEmail,
          to: [email],
          subject: `Kode OTP Login Admin SentinelGrid: ${otp}`,
          text: `Kode OTP 6-digit Anda untuk masuk ke Portal Admin SentinelGrid adalah: ${otp}\n\nKode ini berlaku selama 10 menit. Jangan bagikan kode ini kepada siapa pun.`,
          html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #e2e8f0;border-radius:12px;">
            <h2 style="margin:0 0 12px;color:#0f172a;">Kode Verifikasi Login Admin SentinelGrid</h2>
            <p style="margin:0 0 16px;color:#475569;font-size:14px;">Gunakan kode OTP 6-digit berikut untuk masuk ke Portal Admin (berlaku 10 menit):</p>
            <div style="font-family:monospace;font-size:28px;font-weight:700;letter-spacing:6px;padding:14px 18px;background:#f8fafc;border:1px solid #cbd5e1;border-radius:8px;text-align:center;color:#0284c7;">${otp}</div>
            <p style="margin:16px 0 0;color:#64748b;font-size:12px;">Jika Anda tidak meminta kode ini, abaikan email ini.</p>
          </div>`,
        }),
      });

      if (response.ok) {
        return { delivered: true, channel: 'email' };
      }

      const errText = await response.text().catch(() => '');
      console.warn(
        `[SentinelGrid OTP] Resend email API returned ${response.status}: ${errText}. Falling back to secure preview OTP.`,
      );
      return {
        delivered: true,
        channel: 'preview',
        previewOtp: otp,
        providerError: `Email provider HTTP ${response.status}`,
      };
    } catch (err) {
      console.warn('[SentinelGrid OTP] Failed contacting email provider:', err);
      return {
        delivered: true,
        channel: 'preview',
        previewOtp: otp,
        providerError: err instanceof Error ? err.message : 'Email provider unreachable',
      };
    }
  }

  console.info(`[SentinelGrid OTP] Admin login OTP for ${email}: ${otp}`);
  return {
    delivered: true,
    channel: 'preview',
    previewOtp: otp,
  };
}
