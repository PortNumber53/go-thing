declare module "@xterm/xterm" {
  export class Terminal {
    constructor(options?: any);
    open(container: HTMLElement): void;
    write(data: string | Uint8Array): void;
    onData(cb: (data: string) => void): void;
    loadAddon(addon: any): void;
    dispose(): void;
    readonly cols: number;
    readonly rows: number;
    resize(cols: number, rows: number): void;
  }
}

declare module "@xterm/addon-fit" {
  export class FitAddon {
    constructor();
    fit(): void;
  }
}

declare module "@xterm/addon-attach" {
  export interface AttachOptions {
    bidirectional?: boolean;
    useBinary?: boolean;
  }
  export class AttachAddon {
    constructor(socket: WebSocket, options?: AttachOptions);
    dispose(): void;
  }
}
