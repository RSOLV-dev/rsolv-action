import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

export default [
  js.configs.recommended,
  ...tsPlugin.configs['flat/recommended'],
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2021,
        sourceType: 'module',
      },
    },
    rules: {
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { 'argsIgnorePattern': '^_', 'varsIgnorePattern': '^_' }],
      '@typescript-eslint/ban-ts-comment': 'warn',
      '@typescript-eslint/no-require-imports': 'warn',
      '@typescript-eslint/no-this-alias': 'warn',
      'no-constant-condition': 'warn',
      'no-case-declarations': 'warn',
      'no-useless-escape': 'warn',
      // Downgraded, not disabled, so the 5 current hits stay visible.
      // New in eslint 10 and it misreads this codebase's deliberate
      // memory-release pattern: ast-pattern-interpreter.ts pairs
      // `let ast: File | null = null` with `finally { ast = null }` to drop a
      // large AST for GC. The rule sees a dead store; the intent is freeing
      // memory, and ast-pattern-interpreter-memory.test.ts guards it.
      // Revisit the remaining hits individually rather than blanket-fixing.
      'no-useless-assignment': 'warn',
      'indent': ['error', 2],
      'linebreak-style': ['error', 'unix'],
      'quotes': ['error', 'single'],
      'semi': ['error', 'always'],
    },
  },
  {
    files: ['**/__tests__/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
    rules: {
      '@typescript-eslint/no-unused-vars': 'warn',
      'no-useless-escape': 'warn',
      'require-yield': 'warn',
      'no-case-declarations': 'warn',
    },
  },
];
