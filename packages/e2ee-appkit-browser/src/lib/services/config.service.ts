export class ConfigService {
  constructor(
    /**
     * backend base url for api calls.
     */
    public readonly backendHost: string,
    public readonly challengeSubmitRoute: string = '/authn/submit-challenge',
    public readonly challengeRetrieveRoute: string = '/authn/get-challenge',
    public readonly loginSubmitRoute: string = '/login',
    public readonly signupRoute: string = '/authn/signup',
    /**
     * Route to redirect user to when `redirectToLogin` function is called.
     */
    public readonly loginFrontendRoute: string = '/login', // used to redirect
  ) {}
}
