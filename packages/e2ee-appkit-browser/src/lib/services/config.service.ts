export class ConfigService {
  constructor(
    public readonly backendHost: string,
    public readonly challengeSubmitRoute: string = '/authn/submit-challenge',
    public readonly challengeRetrieveRoute: string = '/authn/get-challenge',
    public readonly loginSubmitRoute: string = '/login',
    public readonly signupRoute: string = '/authn/signup',
    public readonly loginFrontendRoute: string = '/login',
  ) {}
}
