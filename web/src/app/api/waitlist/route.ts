import { NextRequest, NextResponse } from "next/server";

const NOTION_API_URL = "https://api.notion.com/v1/pages";
const NOTION_DATABASE_ID = process.env.NOTION_WAITLIST_DB_ID!;
const NOTION_API_KEY = process.env.NOTION_API_KEY!;

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

    const response = await fetch(NOTION_API_URL, {
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
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error("Notion API error:", response.status, errorBody);
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
