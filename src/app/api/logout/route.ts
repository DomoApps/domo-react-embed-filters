import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function POST(_req: NextRequest) {
  // Clear the 'token' cookie by setting it to empty and expired
  return NextResponse.json(
    { message: 'Logged out successfully' },
    {
      status: 200,
      headers: {
        'Set-Cookie': 'token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0;'
      }
    }
  );
}
