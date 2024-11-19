import { NextRequest, NextResponse } from 'next/server'

export async function POST(req: NextRequest) {
  const formData = await req.formData()
  const file = formData.get('contract') as File

  if (!file) {
    return NextResponse.json({ error: 'No file uploaded' }, { status: 400 })
  }

  // Create a new FormData object to send to the backend
  const backendFormData = new FormData()
  backendFormData.append('contract', file)

  try {
    const response = await fetch('http://localhost:8080/api/audit', {
      method: 'POST',
      body: backendFormData,
      headers: {
        'Authorization': req.headers.get('Authorization') || '',
      },
    })

    if (response.ok) {
      const result = await response.json()
      return NextResponse.json(result)
    } else {
      throw new Error('Failed to audit contract')
    }
  } catch (error) {
    console.error('Error:', error)
    return NextResponse.json({ error: 'Failed to audit contract' }, { status: 500 })
  }
}
