import typescript from '@rollup/plugin-typescript';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

const config = {
  input: 'src/SecureStorage.ts',
  output: [
    {
      file: 'dist/secure-storage.cjs.js',
      format: 'cjs',
      sourcemap: true
    },
    {
      file: 'dist/secure-storage.esm.js',
      format: 'es',
      sourcemap: true
    },
    {
      file: 'dist/secure-storage.umd.js',
      format: 'umd',
      name: 'SecureStorage',
      sourcemap: true
    }
  ],
  plugins: [
    typescript({
      tsconfig: './tsconfig.json',
      declaration: true,
      declarationDir: './dist/types'
    }),
    nodeResolve(),
    commonjs()
  ]
};

export default config;
