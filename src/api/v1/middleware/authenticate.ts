import { Request, Response, NextFunction } from 'express';
import { auth } from '../../../config/firebaseConfig';


export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.split(' ')[1];

    const decodedToken = await auth.verifyIdToken(token);

    res.locals.uid = decodedToken.uid;
    res.locals.role = decodedToken.role || 'user'; 

    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({ message: 'Unauthorized or invalid token' });
  }
};
