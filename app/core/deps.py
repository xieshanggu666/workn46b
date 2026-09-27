from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.user import User


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="未登录")
    try:
        payload = decode_access_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="登录已失效")
    user = db.get(User, int(payload.get("sub")))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="用户不存在或已禁用")
    return user


def require_roles(*roles: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="无权限执行该操作")
        return user

    return checker


def ensure_company_access(user: User, company_id: int | None, detail: str = "无权访问该企业数据") -> None:
    """统一企业数据归属校验。

    权限边界：enterprise 用户仅能访问本企业（company_id）数据；
    admin / verifier 为平台侧角色，可跨企业访问。
    """
    if user.role == "enterprise" and user.company_id != company_id:
        raise HTTPException(status_code=403, detail=detail)
