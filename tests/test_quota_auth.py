"""配额交易接口越权（IDOR）回归测试。

重点：enterprise 用户只能访问本企业的配额账户与交易明细；
admin / verifier 作为平台侧角色可跨企业访问；未登录一律 401。
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.core.security import hash_password
from app.main import app
from app.models import AllowanceAccount, AllowanceTransaction, Company, Quota, User


@pytest.fixture()
def ctx():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    c1 = Company(code="C-001", name="绿能电力", industry="电力", region="华东")
    c2 = Company(code="C-002", name="恒固水泥", industry="水泥", region="华北")
    db.add_all([c1, c2])
    db.flush()

    pwd_hash, salt = hash_password("123456")
    db.add_all(
        [
            User(username="admin", display_name="监管管理员", role="admin", password_hash=pwd_hash, salt=salt),
            User(username="verifier", display_name="核查员", role="verifier", password_hash=pwd_hash, salt=salt),
            User(username="elec", display_name="电力企业", role="enterprise", company_id=c1.id, password_hash=pwd_hash, salt=salt),
            User(username="cement", display_name="水泥企业", role="enterprise", company_id=c2.id, password_hash=pwd_hash, salt=salt),
        ]
    )

    accounts = []
    for company in (c1, c2):
        db.add(
            Quota(
                company_id=company.id, year=2025, baseline=1000,
                allocation_amount=800, adjustment=0, total=800, status="allocated",
            )
        )
        db.flush()
        account = AllowanceAccount(
            company_id=company.id, year=2025,
            opening_balance=800, current_balance=800, frozen_balance=0,
        )
        db.add(account)
        db.flush()
        accounts.append(account)
        db.add(
            AllowanceTransaction(
                account_id=account.id, company_id=company.id, tx_type="allocation",
                amount=800, tx_date="2025-01-10", balance_after=800, remark="免费配额入账",
            )
        )
    db.commit()

    ids = {
        "c1": c1.id,
        "c2": c2.id,
        "acct1": accounts[0].id,
        "acct2": accounts[1].id,
    }

    def override_get_db():
        session = Session()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, ids
    finally:
        app.dependency_overrides.clear()
        db.close()
        engine.dispose()


def login(client, username):
    client.cookies.clear()
    res = client.post("/api/auth/login", json={"username": username, "password": "123456"})
    assert res.status_code == 200
    return client


def test_enterprise_can_read_own_transactions(ctx):
    client, ids = ctx
    login(client, "elec")
    res = client.get(f"/api/accounts/{ids['acct1']}/transactions")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["remark"] == "免费配额入账"


def test_enterprise_cannot_read_other_company_transactions(ctx):
    """越权回归：企业不得通过遍历 account_id 拉取其他企业交易明细。"""
    client, ids = ctx
    login(client, "elec")
    res = client.get(f"/api/accounts/{ids['acct2']}/transactions")
    assert res.status_code == 403
    assert res.json() == {"detail": "无权查看该账户交易明细"}


def test_enterprise_cannot_transfer_other_company_account(ctx):
    """越权回归：企业不得操作其他企业配额账户。"""
    client, ids = ctx
    login(client, "elec")
    res = client.post(
        f"/api/accounts/{ids['acct2']}/transfer",
        json={"amount": 1, "tx_type": "sell"},
    )
    assert res.status_code == 403


def test_enterprise_cannot_read_other_company_account(ctx):
    client, ids = ctx
    login(client, "elec")
    res = client.get(f"/api/companies/{ids['c2']}/account?year=2025")
    assert res.status_code == 403


def test_enterprise_cannot_read_other_company_totals(ctx):
    """统一权限边界：企业访问其他企业的任何数据接口均被拒绝。"""
    client, ids = ctx
    login(client, "elec")
    res = client.get(f"/api/companies/{ids['c2']}/totals?year=2025")
    assert res.status_code == 403


def test_enterprise_quota_list_only_returns_own_company(ctx):
    """列表接口也必须按企业过滤，不泄露其他企业配额。"""
    client, ids = ctx
    login(client, "elec")
    res = client.get("/api/quotas")
    assert res.status_code == 200
    data = res.json()
    assert data, "应能看到本企业配额"
    assert all(item["company_id"] == ids["c1"] for item in data)


def test_admin_can_read_any_company_transactions(ctx):
    client, ids = ctx
    login(client, "admin")
    res = client.get(f"/api/accounts/{ids['acct2']}/transactions")
    assert res.status_code == 200
    assert len(res.json()) == 1


def test_verifier_can_read_any_company_transactions(ctx):
    """核查员为平台侧角色，可跨企业查看交易明细。"""
    client, ids = ctx
    login(client, "verifier")
    res = client.get(f"/api/accounts/{ids['acct2']}/transactions")
    assert res.status_code == 200


def test_transactions_requires_login(ctx):
    client, ids = ctx
    client.cookies.clear()
    res = client.get(f"/api/accounts/{ids['acct1']}/transactions")
    assert res.status_code == 401


def test_transactions_nonexistent_account_returns_404(ctx):
    client, ids = ctx
    login(client, "elec")
    res = client.get("/api/accounts/9999/transactions")
    assert res.status_code == 404
