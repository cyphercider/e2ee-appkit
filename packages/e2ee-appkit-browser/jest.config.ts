/* eslint-disable */

export default {
  displayName: 'e2ee-appkit-browser',
  preset: '../../jest.preset.js',
  transform: {
    '^.+\\.[tj]sx?$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }],
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx'],
  coverageDirectory: '../../coverage/packages/e2ee-appkit-browser',
  testEnvironment: '../../jest-node-env.ts',
}
