export type User = { id: number; username: string; name: string }

export type LoginSuccess = { user: User }

export function isUser(o: unknown): o is User {
  return !!o &&
    typeof o === 'object' &&
    'id' in (o as any) && typeof (o as any).id === 'number' &&
    'name' in (o as any) && typeof (o as any).name === 'string' &&
    'username' in (o as any) && typeof (o as any).username === 'string'
}

export function isLoginSuccess(d: unknown): d is LoginSuccess {
  return !!d && typeof d === 'object' && 'user' in (d as any) && isUser((d as any).user)
}
