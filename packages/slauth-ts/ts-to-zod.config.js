/**
 * ts-to-zod configuration for slauth
 * 
 * @type {import("ts-to-zod").TsToZodConfig}
 */
module.exports = [
  {
    name: "auth-api",
    input: "src/types/auth-api.ts",
    output: "src/schemas/auth-api.schemas.ts",
    getSchemaName: (id) => {
      
      const cleanId = id
        .replace(/^PkgController/, '')
        .replace(/^GithubComThecybersailorSlauthPkgTypes/, '');
      return `${cleanId}Schema`;
    },
    
    skipParseJSDoc: false,
    
    customJSDocFormatTypes: {
      "date-time": "z.string().datetime()",
      "date": "z.string().date()", 
      "email": "z.string().email()",
      "url": "z.string().url()",
      "uuid": "z.string().uuid()"
    }
  },
  {
    name: "admin-api", 
    input: "src/types/admin-api.ts",
    output: "src/schemas/admin-api.schemas.ts",
    getSchemaName: (id) => {
      
      const cleanId = id
        .replace(/^PkgController/, '')
        .replace(/^GithubComThecybersailorSlauthPkgTypes/, '');
      return `${cleanId}Schema`;
    },
    skipParseJSDoc: false,
    customJSDocFormatTypes: {
      "date-time": "z.string().datetime()",
      "date": "z.string().date()",
      "email": "z.string().email()",
      "url": "z.string().url()",
      "uuid": "z.string().uuid()"
    }
  }
];
