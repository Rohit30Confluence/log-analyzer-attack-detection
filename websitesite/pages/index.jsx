import Image from "next/image";
import Link from "next/link";
import ChartDemo from "@/components/ChartDemo";

export default function Home() {
  return (
    <main className="min-h-screen bg-gray-50 text-gray-800">
      <header className="bg-gray-900 text-white py-10 text-center">
        <div className="container mx-auto">
          <Image
            src="/banner.svg"
            alt="Project Banner"
            width={1280}
            height={320}
            className="mx-auto"
          />
          <h1 className="text-4xl font-bold mt-6">
            Log Analyzer & Attack Detection
          </h1>
          <p className="text-gray-300 mt-2">
            Detect. Analyze. Defend. Unified security intelligence for Apache logs.
          </p>
          <div className="mt-6">
            <Link href="/docs" className="bg-blue-600 hover:bg-blue-700 px-5 py-2 rounded text-white">
              View Documentation →
            </Link>
          </div>
        </div>
      </header>

      <section className="container mx-auto py-16 px-4">
        <h2 className="text-2xl font-semibold mb-6">System Architecture</h2>
        <Image
          src="/architecture.svg"
          alt="Architecture Diagram"
          width={1000}
          height={300}
          className="shadow rounded-lg border border-gray-200"
        />
      </section>

      <section className="container mx-auto py-16 px-4 bg-white">
        <h2 className="text-2xl font-semibold mb-6">Demo Visualization</h2>
        <ChartDemo />
      </section>

      <footer className="text-center py-10 bg-gray-900 text-gray-400 text-sm">
        © 2025 Log Analyzer Project • Built with Next.js + Tailwind
      </footer>
    </main>
  );
}
