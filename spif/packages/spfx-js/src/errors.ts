/**
 * Custom error hierarchy for SPIF.
 */

export class SPIFError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SPIFError';
  }
}

export class SPIFMagicError extends SPIFError {
  constructor(message: string) {
    super(message);
    this.name = 'SPIFMagicError';
  }
}

export class SPIFVersionError extends SPIFError {
  constructor(message: string) {
    super(message);
    this.name = 'SPIFVersionError';
  }
}

export class SPIFChecksumError extends SPIFError {
  constructor(message: string) {
    super(message);
    this.name = 'SPIFChecksumError';
  }
}

export class SPIFSignatureError extends SPIFError {
  constructor(message: string) {
    super(message);
    this.name = 'SPIFSignatureError';
  }
}

export class SPIFFormatError extends SPIFError {
  constructor(message: string) {
    super(message);
    this.name = 'SPIFFormatError';
  }
}
