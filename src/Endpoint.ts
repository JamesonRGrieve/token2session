import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function proxyRequest(
  request: NextRequest, 
  pathSegments: string[], 
  method: string
): Promise<NextResponse> {
  // Ensure AUTH_SERVER environment variable is set
  const authServer = process.env.AUTH_SERVER;
  if (!authServer) {
    return NextResponse.json(
      { error: 'AUTH_SERVER environment variable is not set' }, 
      { status: 500 }
    );
  }

  // Extract session ID from headers
  const sessionId = request.headers.get('x-session-id');
  if (!sessionId) {
    return NextResponse.json(
      { error: 'Session ID is required' }, 
      { status: 401 }
    );
  }

  try {
    // Find session and associated TokenUser
    const session = await prisma.session.findUnique({
      where: { id: sessionId },
      include: { tokenUser: true }
    });

    if (!session) {
      return NextResponse.json(
        { error: 'Invalid session' }, 
        { status: 401 }
      );
    }

    // Check session expiration
    if (session.expiresAt < new Date()) {
      return NextResponse.json(
        { error: 'Session expired' }, 
        { status: 401 }
      );
    }

    // Construct the full path by joining path segments
    const pathString = pathSegments.join('/');
    const targetUrl = `${authServer.replace(/\/$/, '')}/${pathString}`;

    // Copy headers from the original request
    const headers = new Headers(request.headers);
    
    // Remove Next.js specific headers if needed
    headers.delete('host');
    headers.delete('connection');
    headers.delete('x-session-id'); // Remove session ID header

    // Add Authorization header with JWT
    headers.set('Authorization', `Bearer ${session.tokenUser.jwt}`);

    // Forward the request
    const response = await fetch(targetUrl, {
      method,
      headers,
      body: method !== 'GET' && method !== 'HEAD' ? await request.text() : undefined,
    });

    // Create a new response with the proxied response's body and status
    // Carefully control which headers are passed through
    const responseHeaders = new Headers();
    response.headers.forEach((value, key) => {
      // Only pass through safe, standard headers
      const safeHeaders = [
        'content-type', 
        'cache-control', 
        'pragma', 
        'expires', 
        'etag', 
        'last-modified'
      ];
      if (safeHeaders.includes(key.toLowerCase())) {
        responseHeaders.set(key, value);
      }
    });

    return new NextResponse(response.body, {
      status: response.status,
      headers: responseHeaders
    });
  } catch (error) {
    console.error('Proxy request error:', error);
    return NextResponse.json(
      { error: 'Failed to proxy request' }, 
      { status: 500 }
    );
  } finally {
    // Ensure Prisma connection is closed
    await prisma.$disconnect();
  }
}

export default proxyRequest;