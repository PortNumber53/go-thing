export type User = { id: number; username: string; name: string }

export type LoginSuccess = { user: User }

export function isUser(o: unknown): o is User {
  if (typeof o !== 'object' || o === null) {
    return false;
  }
  const obj = o as Record<string, unknown>;
  return (
    typeof obj.id === 'number' &&
    typeof obj.name === 'string' &&
    typeof obj.username === 'string'
  );
}

export function isLoginSuccess(d: unknown): d is LoginSuccess {
  return !!d && typeof d === 'object' && 'user' in (d as any) && isUser((d as any).user)
}
