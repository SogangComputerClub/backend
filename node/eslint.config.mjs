import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier";

/**
 * @type {import('eslint').Linter.Config[]}
 */
export default [
  ...tseslint.config(
    eslint.configs.recommended,
    tseslint.configs.recommended,
    {
      languageOptions: {
        parserOptions: {
          projectService: true,
          tsconfigRootDir: import.meta.dirname,
        },
      },
    },
    tseslint.configs.stylisticTypeChecked,
  ),
  eslintConfigPrettier,
];
