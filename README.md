# E2EE Toolkit

## Motivation

End-to-end encryption allows a user to store data on a remote system without the remote system being able to access the data.

## Toolkit Overview

The toolkit publishes three libraries: 

- [E2EE Appkit Node](https://www.npmjs.com/package/@cyphercider/e2ee-appkit-node)
- [E2EE Appkit Browser](https://www.npmjs.com/package/@cyphercider/e2ee-appkit-browser)
- [E2EE Appkit Shared Models](https://www.npmjs.com/package/@cyphercider/e2ee-appkit-shared-models)


For usage information, see readmes:

- [Appkit Browser Readme](./packages/e2ee-appkit-browser/README.md)
- [Appkit Node Readme](./packages/e2ee-appkit-node/README.md)

## Publish process

1. run `pnpm run build`
2. CD into each affected repo and run `pnpm publish`


