import { useState } from "react";
import zxcvbn from "zxcvbn";

const PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com/range";

async function sha1(value) {
  const data = new TextEncoder().encode(value);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  return hashArray
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

async function checkPwnedPassword(password) {
  const passwordHash = await sha1(password);
  const prefix = passwordHash.slice(0, 5);
  const suffix = passwordHash.slice(5);

  const response = await fetch(`${PWNED_PASSWORDS_API}/${prefix}`);

  if (!response.ok) {
    throw new Error("Erro ao consultar senhas vazadas");
  }

  const hashes = await response.text();
  const leakedHash = hashes
    .split("\n")
    .map((line) => line.trim().split(":"))
    .find(([hashSuffix]) => hashSuffix === suffix);

  return {
    pwned: Boolean(leakedHash),
    count: leakedHash ? Number(leakedHash[1]) : 0,
  };
}

function App() {
  const [password, setPassword] = useState("");
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  async function checkPassword() {
    if (!password) {
      setResult(null);
      setError("Digite uma senha para verificar.");
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      const pwnedResult = await checkPwnedPassword(password);
      const strength = zxcvbn(password);

      setResult({
        ...pwnedResult,
        score: strength.score,
        feedback: strength.feedback,
      });
    } catch (err) {
      console.log(err);
      setResult(null);
      setError("Não foi possível verificar a senha agora.");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-white flex items-center justify-center">
      <div className="bg-zinc-900 p-8 rounded-2xl w-[400px] shadow-2xl">
        <h1 className="text-3xl font-bold mb-6">
          Testador de senhas
	  
        </h1>

        <input
          type="password"
          placeholder="Digite uma senha..."
          className="w-full p-3 rounded-lg bg-zinc-800 outline-none"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button
          onClick={checkPassword}
          disabled={isLoading}
          className="w-full mt-4 bg-red-500 hover:bg-red-600 transition p-3 rounded-lg font-bold"
        >
          {isLoading ? "Verificando..." : "Verificar"}
        </button>

        {error && (
          <p className="mt-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {result && (
          <div className="mt-6">
            <p>
              Vazou:
              {" "}
              {result.pwned ? "Sua senha foi comprometida!" : "Sua senha está a salvo!"}
            </p>

            <p className="mt-2">
              Ocorrências:
              {" "}
              {result.count}
            </p>

            <p className="mt-2">
              Score:
              {" "}
              {result.score}/4
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
