import type { SignatureDefinition } from '../signatures';

// Note: Detecting databases purely from client-side accessible information is often difficult and unreliable.
// These patterns are mostly based on error messages or very specific clues.
export const databasesSignatures: SignatureDefinition[] = [
  {
    name: "MySQL",
    weight: 0.7,
    patterns: [
      { type: "html", pattern: /mysql_connect|mysqli_connect|pdo::__construct/i, weight: 0.4 }, // PHP functions in error messages
      { type: "error", pattern: /MySQL connect error|Supplied argument is not a valid MySQL result resource/i, weight: 0.8 } // Error messages
    ]
  },
  {
    name: "PostgreSQL",
    weight: 0.7,
    patterns: [
      { type: "html", pattern: /pg_connect|PDO::__construct\(.*pgsql/i, weight: 0.4 }, // PHP functions in error messages
      { type: "error", pattern: /PostgreSQL.*error|pg_query\(\): Query failed/i, weight: 0.8 } // Error messages
    ]
  },
  {
    name: "MongoDB",
    weight: 0.7,
    patterns: [
      // MongoDB detection is very hard from client-side. Look for specific XHR patterns if API is exposed.
      { type: "html", pattern: /MongoDB driver/i, weight: 0.5 }, // Error messages
      { type: "jsGlobal", pattern: "MongoDB" } // Unlikely to be exposed directly
    ]
  },
  {
    name: "Redis",
    weight: 0.7,
    patterns: [
      { type: "header", pattern: "x-redis-info" }, // Custom header, rare
      { type: "error", pattern: /Redis server connection error|Connection to Redis failed/i, weight: 0.8 },
      { type: "jsGlobal", pattern: "Redis" } // Unlikely
    ]
  }
];
