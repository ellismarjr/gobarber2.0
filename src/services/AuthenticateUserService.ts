import { getRepository } from 'typeorm';
import { compare } from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';

import User from '../models/Users';

interface Request {
  email: string;
  password: string;
}

interface Response {
  user: User;
  token: string;
}

class AuthenticateUserService {
  public async execute({ email, password }: Request): Promise<Response> {
    const usersRepository = getRepository(User);

    const user = await usersRepository.findOne({ where: { email } });

    if (!user) {
      throw new Error('Incorrect email/password combination!');
    }

    const passwordMatched = await compare(password, user.password);

    if (!passwordMatched) {
      throw new Error('Incorrect email/password combination!');
    }

    const token = sign(
      {},
      '258676D0650D24D02B7C6BE0A395A0074B6A660AF299A02375B7E291D13139F01666BF022D0C808B3FF10A508839FEE74629495B8C64FF079D4BE8FA43D35D77',
      { subject: user.id, expiresIn: '1d' },
    );

    return { user, token };
  }
}

export default AuthenticateUserService;
