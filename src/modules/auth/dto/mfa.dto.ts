import { ApiProperty } from '@nestjs/swagger';
import { IsString, Matches } from 'class-validator';

/** Body for the code-verifying MFA routes (enable / disable / session). A 6-digit TOTP code. */
export class MfaCodeDto {
  @ApiProperty({ description: 'The 6-digit code from the authenticator app', example: '123456' })
  @IsString()
  @Matches(/^\d{6}$/, { message: 'code must be a 6-digit number' })
  code!: string;
}
