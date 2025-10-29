"use client";
import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from "recharts";

export default function ChartDemo() {
  const data = [
    { name: "SQL Injection", attacks: 8 },
    { name: "Brute Force", attacks: 14 },
    { name: "XSS", attacks: 5 },
    { name: "Anomaly", attacks: 3 }
  ];

  return (
    <div className="bg-gray-100 p-6 rounded-lg shadow">
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip />
          <Bar dataKey="attacks" fill="#2563eb" radius={[6, 6, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
