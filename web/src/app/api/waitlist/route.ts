import { NextRequest, NextResponse } from "next/server";
import { Resend } from "resend";

const NOTION_API_URL = "https://api.notion.com/v1/pages";
const NOTION_DATABASE_ID = process.env.NOTION_WAITLIST_DB_ID!;
const NOTION_API_KEY = process.env.NOTION_API_KEY!;

function getResend() {
  return new Resend(process.env.RESEND_API_KEY);
}

export async function POST(req: NextRequest) {
  try {
    const { email } = await req.json();

    if (!email || typeof email !== "string") {
      return NextResponse.json(
        { error: "Email is required" },
        { status: 400 }
      );
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return NextResponse.json(
        { error: "Invalid email address" },
        { status: 400 }
      );
    }

    // Save to Notion and send email notification in parallel
    const [notionResult, emailResult] = await Promise.allSettled([
      // 1. Save to Notion database
      fetch(NOTION_API_URL, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${NOTION_API_KEY}`,
          "Content-Type": "application/json",
          "Notion-Version": "2022-06-28",
        },
        body: JSON.stringify({
          parent: { database_id: NOTION_DATABASE_ID },
          properties: {
            Email: {
              title: [{ text: { content: email } }],
            },
            Source: {
              select: { name: "landing_page" },
            },
            Status: {
              select: { name: "new" },
            },
          },
        }),
      }),

      // 2. Send email notification
      getResend().emails.send({
        from: "AgentGuard <notifications@stridemap.ai>",
        to: "support@stridemap.ai",
        subject: `New waitlist signup: ${email}`,
        html: `
          <div style="font-family: system-ui, sans-serif; max-width: 480px;">
            <h2 style="color: #00D4AA; margin-bottom: 4px;">New Waitlist Signup</h2>
            <p style="color: #666; margin-top: 0;">Someone just joined the AgentGuard early access list.</p>
            <table style="border-collapse: collapse; width: 100%;">
              <tr>
                <td style="padding: 8px 12px; border: 1px solid #eee; font-weight: 600;">Email</td>
                <td style="padding: 8px 12px; border: 1px solid #eee;">${email}</td>
              </tr>
              <tr>
                <td style="padding: 8px 12px; border: 1px solid #eee; font-weight: 600;">Source</td>
                <td style="padding: 8px 12px; border: 1px solid #eee;">Landing Page</td>
              </tr>
              <tr>
                <td style="padding: 8px 12px; border: 1px solid #eee; font-weight: 600;">Time</td>
                <td style="padding: 8px 12px; border: 1px solid #eee;">${new Date().toISOString()}</td>
              </tr>
            </table>
            <p style="color: #999; font-size: 12px; margin-top: 16px;">
              View all signups in <a href="https://notion.so" style="color: #00D4AA;">Notion → AgentGuard → Waitlist Signups</a>
            </p>
          </div>
        `,
      }),
    ]);

    // Log failures but don't block the user
    if (notionResult.status === "rejected") {
      console.error("Notion API error:", notionResult.reason);
    } else {
      const notionResponse = notionResult.value;
      if (!notionResponse.ok) {
        console.error("Notion API error:", notionResponse.status, await notionResponse.text());
      }
    }

    if (emailResult.status === "rejected") {
      console.error("Email send error:", emailResult.reason);
    }

    // Return success as long as at least one succeeded
    const notionOk = notionResult.status === "fulfilled" && notionResult.value.ok;
    const emailOk = emailResult.status === "fulfilled";

    if (!notionOk && !emailOk) {
      return NextResponse.json(
        { error: "Failed to save signup" },
        { status: 502 }
      );
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Waitlist signup error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
