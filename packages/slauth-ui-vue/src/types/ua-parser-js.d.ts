declare module 'ua-parser-js' {
  interface IResult {
    browser: {
      name?: string
      version?: string
    }
    os: {
      name?: string
      version?: string
    }
    device: {
      type?: string
      model?: string
    }
  }

  class UAParser {
    constructor(userAgent?: string)
    setUA(userAgent: string): UAParser
    getResult(): IResult
  }

  export = UAParser
}
