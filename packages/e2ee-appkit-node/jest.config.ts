/* eslint-disable */
export default {
  displayName: 'e2ee-appkit-node',
  preset: '../../jest.preset.js',
  testEnvironment: 'node',
  transform: {
    '^.+\\.[tj]sx?$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.spec.json' }],
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx'],
  coverageDirectory: '../../coverage/packages/e2ee-appkit-node',
  coveragePathIgnorePatterns: ['.*crypto-test.service.ts'],
}
