interface CreationInput {
  challenge: string;
  user: { id: string; name?: string; displayName?: string } & Record<string, unknown>;
  excludeCredentials?: Array<{ id: string; type?: string; transports?: string[] }>;
  [key: string]: unknown;
}

interface RequestInput {
  challenge: string;
  allowCredentials?: Array<{ id: string; type?: string; transports?: string[] }>;
  [key: string]: unknown;
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function passkeysSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator !== "undefined" &&
    typeof navigator.credentials?.create === "function"
  );
}

export async function createPasskeyCredential(
  publicKey: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const input = publicKey as unknown as CreationInput;
  const creationOptions: PublicKeyCredentialCreationOptions = {
    ...(publicKey as unknown as Record<string, unknown>),
    challenge: base64UrlToBytes(input.challenge).buffer as ArrayBuffer,
    user: {
      ...(input.user as unknown as Record<string, unknown>),
      id: base64UrlToBytes(input.user.id).buffer as ArrayBuffer,
    } as PublicKeyCredentialUserEntity,
    excludeCredentials: input.excludeCredentials?.map(
      (credential): PublicKeyCredentialDescriptor => ({
        type: "public-key",
        id: base64UrlToBytes(credential.id).buffer as ArrayBuffer,
        ...(credential.transports
          ? { transports: credential.transports as AuthenticatorTransport[] }
          : {}),
      }),
    ),
  } as PublicKeyCredentialCreationOptions;
  const credential = (await navigator.credentials.create({
    publicKey: creationOptions,
  })) as
    | (PublicKeyCredential & {
        response: AuthenticatorAttestationResponse;
      })
    | null;
  if (!credential) throw new Error("The authenticator did not return a credential.");
  return {
    id: credential.id,
    raw_id: credential.id,
    transports: credential.response.getTransports?.() ?? [],
    attestationObject: bytesToBase64Url(credential.response.attestationObject),
    clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
  };
}

export async function getPasskeyAssertion(
  publicKey: Record<string, unknown>,
  mediation?: "conditional",
): Promise<Record<string, unknown>> {
  const input = publicKey as unknown as RequestInput;
  const requestOptions: PublicKeyCredentialRequestOptions = {
    ...(publicKey as unknown as Record<string, unknown>),
    challenge: base64UrlToBytes(input.challenge).buffer as ArrayBuffer,
    allowCredentials: input.allowCredentials?.map((credential): PublicKeyCredentialDescriptor => ({
      type: "public-key",
      id: base64UrlToBytes(credential.id).buffer as ArrayBuffer,
      ...(credential.transports
        ? { transports: credential.transports as AuthenticatorTransport[] }
        : {}),
    })),
  } as PublicKeyCredentialRequestOptions;
  const credential = (await navigator.credentials.get({
    publicKey: requestOptions,
    ...(mediation ? { mediation } : {}),
  })) as
    | (PublicKeyCredential & {
        response: AuthenticatorAssertionResponse & { userHandle: ArrayBuffer | null };
      })
    | null;
  if (!credential) throw new Error("The authenticator did not return an assertion.");
  return {
    id: credential.id,
    raw_id: credential.id,
    authenticatorData: bytesToBase64Url(credential.response.authenticatorData),
    signature: bytesToBase64Url(credential.response.signature),
    clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
    userHandle: credential.response.userHandle
      ? bytesToBase64Url(credential.response.userHandle)
      : undefined,
  };
}
