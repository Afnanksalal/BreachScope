import readline from "readline";

/** Prompt for visible text input */
export function promptText(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/** Prompt for a secret — input is masked with * */
export function promptSecret(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(question);

    let value = "";

    const onData = (chunk: Buffer) => {
      const char = chunk.toString("utf8");
      if (char === "\r" || char === "\n") {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.removeListener("data", onData);
        process.stdout.write("\n");
        resolve(value);
      } else if (char === "") {
        // Ctrl+C
        process.stdout.write("\n");
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.exit(0);
      } else if (char === "" || char === "\b") {
        // Backspace
        if (value.length > 0) {
          value = value.slice(0, -1);
          process.stdout.write("\b \b");
        }
      } else {
        value += char;
        process.stdout.write("*");
      }
    };

    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on("data", onData);
  });
}

/** Y/n confirmation prompt — defaults to yes */
export async function promptConfirm(question: string): Promise<boolean> {
  const answer = await promptText(`${question} [Y/n] `);
  return answer === "" || /^y(es)?$/i.test(answer);
}

/**
 * Holds credentials in memory with a destroy() method that zeros all values.
 * JavaScript strings are immutable so true zeroing isn't possible, but we clear
 * all references and replace the internal map so GC can collect them.
 */
export class SecureStore {
  private store: Map<string, string> = new Map();

  set(key: string, value: string): void {
    this.store.set(key, value);
  }

  get(key: string): string | undefined {
    return this.store.get(key);
  }

  toRecord(): Record<string, string> {
    return Object.fromEntries(this.store.entries());
  }

  /** Overwrite all values with empty strings and clear the map */
  destroy(): void {
    for (const key of this.store.keys()) {
      this.store.set(key, "");
    }
    this.store.clear();
  }
}
