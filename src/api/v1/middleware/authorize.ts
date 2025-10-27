import { Request, Response, NextFunction } from "express";
import { HTTP_STATUS } from "../../../constants/httpConstants";

interface Options {
  roles?: string[];          // which roles are allowed
  allowSameUser?: boolean;   // allow a user to access their own resource
}

/**
 * Role-based authorization middleware.
 * @param options { roles, allowSameUser }
 * Usage: authorize({ roles: ['admin'], allowSameUser: true })
 */
export const authorize =
  (options: Options = {}) =>
  (req: Request, res: Response, next: NextFunction): void => {
    const { roles = [], allowSameUser = false } = options;

    // Values set by authenticate middleware
    const currentUserRole: string = res.locals.role;
    const currentUserId: string = res.locals.uid;
    const requestedUserId: string = req.params.id;

    //  Allow if user is accessing their own resource
    if (allowSameUser && currentUserId === requestedUserId) {
      return next();
    }

    //  Allow if user has one of the required roles
    if (roles.length > 0 && roles.includes(currentUserRole)) {
      return next();
    }

    //  Otherwise deny access
    return res.status(HTTP_STATUS.FORBIDDEN).json({
      success: false,
      error: "Access denied: insufficient permissions",
    });
  };
