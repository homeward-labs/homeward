"""
撤销契约端到端测试（adapters/base.py）

用一个假 Enforcer（``FakeDnsBlackholeEnforcer``）把「30 分钟内可一键撤销」这句
承诺完整跑一遍往返：apply → 留下结构化 revert_payload → revert → verify_revert。

覆盖的问题编号（与 03-revert-contract-2026-09-24.md 报告一致）：
  P1 revert_payload 是无 schema 的空 dict
  P2 revert(action_id) 拿不到当初 apply 的信息
  P3 没有任何回滚后核验
  P4 expires_at 语义二义（一键窗口 vs 自动解除）
  P5 窗口过期后没有补救通道

运行方式（仓库根目录，不需要装 pytest）：

    python -m unittest tests/test_revert_contract.py -v
    python tests/test_revert_contract.py          # 等价

说明：本文件只用标准库，且**不安装任何包到全局环境**；``src`` 目录由本文件自行
插入 sys.path，因此无论从哪个工作目录运行都能找到 ``adapters`` 包。
"""

from __future__ import annotations

import os
import sys
import unittest

# —— 让本文件可以从任意工作目录直接跑：把 src/ 挂到 sys.path 上 ——
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC_DIR = os.path.join(_REPO_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from adapters.base import (  # noqa: E402
    REDEEM_WINDOW_SECONDS,
    ActionRegistry,
    Capabilities,
    DnsBlackholePayload,
    EnforceAction,
    EnforceResult,
    Enforcer,
    ProbeResult,
    RevertContractError,
    RevertResult,
    assert_revert_contract,
    validate_applied,
)

T0 = 1_700_000_000.0  # 固定"现在"，避免测试依赖真实时钟


class FakeDnsBlackholeEnforcer(Enforcer):
    """假 DNS 黑洞执行器：用一个内存 dict 冒充配置文件系统

    之所以自己造假 Enforcer 而不是 mock：撤销契约的价值在于**整个往返链路**
    （apply 留 payload → revert 消费 payload → verify 真的去看底层状态），
    只 mock 返回值会把「撤销成功但没真恢复」这类问题整体跳过。

    sabotage_* 开关用来人为制造「命令成功但状态没恢复」的场景，这正是 P3 要抓的。
    """

    CONFIG_PATH = "/etc/dnsmasq.d/iot-block.conf"

    def __init__(
        self,
        *,
        emit_payload: bool = True,
        sabotage_removal: bool = False,
        sabotage_reload: bool = False,
    ) -> None:
        self.fs: dict[str, str] = {}
        self.emit_payload = emit_payload
        self.sabotage_removal = sabotage_removal
        self.sabotage_reload = sabotage_reload
        self.reloaded = False
        self.revert_calls = 0

    # —— 只在测试里用到的辅助 ——

    def config_contains(self, entry: str) -> bool:
        return entry in self.fs.get(self.CONFIG_PATH, "")

    # —— Enforcer 接口实现 ——

    def probe(self) -> ProbeResult:
        return ProbeResult(True, "fake dnsmasq ready", self.capabilities())

    def capabilities(self) -> Capabilities:
        return Capabilities(enforce_soft=True, is_lan_dns=True)

    def apply(self, action: EnforceAction) -> EnforceResult:
        entry = f"address=/{action.target}/0.0.0.0"
        existed = self.CONFIG_PATH in self.fs
        backup_path: str | None
        if existed:
            backup_path = self.CONFIG_PATH + ".bak"
            self.fs[backup_path] = self.fs[self.CONFIG_PATH]
        else:
            backup_path = None
            self.fs[self.CONFIG_PATH] = ""

        self.fs[self.CONFIG_PATH] = self.fs[self.CONFIG_PATH] + entry + "\n"

        if not self.emit_payload:
            # 故意违反契约：规则生效了，却什么回滚信息都不留
            return EnforceResult(ok=True, action_id=action.action_id, message="已下发（未留回滚信息）")

        action.revert_payload = DnsBlackholePayload(
            config_path=self.CONFIG_PATH,
            entry=entry,
            backup_path=backup_path,
            created_file=not existed,
            reload_required=True,
            reload_command=("systemctl", "reload", "dnsmasq"),
            resolver_process="dnsmasq",
        )
        return EnforceResult(ok=True, action_id=action.action_id, message="已下发 DNS 黑洞")

    def revert(self, action: EnforceAction) -> RevertResult:
        """幂等回滚：条目已不存在时同样返回 ok=True"""
        self.revert_calls += 1
        payload = action.revert_payload
        if payload is None:
            return RevertResult(ok=False, action_id=action.action_id, message="无 revert_payload")

        if not self.sabotage_removal:
            content = self.fs.get(payload.config_path, "")
            kept = [line for line in content.splitlines() if line != payload.entry]
            if payload.created_file and not kept:
                self.fs.pop(payload.config_path, None)  # 本次新建的文件：整个删掉
            else:
                self.fs[payload.config_path] = "\n".join(kept)

        if payload.reload_required and not self.sabotage_reload:
            self.reloaded = True

        return RevertResult(
            ok=True,
            action_id=action.action_id,
            message="已移除配置条目" + ("并重载 dnsmasq" if self.reloaded else ""),
        )

    def verify_revert(self, action: EnforceAction) -> RevertResult:
        """真的去看底层状态：条目没了没？进程重载了没？"""
        payload = action.revert_payload
        if payload is None:
            return RevertResult(ok=False, action_id=action.action_id, message="无 revert_payload 可核验")

        if payload.entry in self.fs.get(payload.config_path, ""):
            return RevertResult(
                ok=True,
                action_id=action.action_id,
                verified=False,
                message=f"{payload.config_path} 中仍存在条目「{payload.entry}」，规则未真正解除",
                evidence=f"file={payload.config_path}",
            )
        if payload.reload_required and not self.reloaded:
            return RevertResult(
                ok=True,
                action_id=action.action_id,
                verified=False,
                message="配置已回滚，但解析器进程未重载，进程内存里规则仍然生效",
                evidence=f"process={payload.resolver_process}",
            )
        return RevertResult(
            ok=True,
            action_id=action.action_id,
            verified=True,
            message=f"已确认 {payload.config_path} 中无该条目，且 dnsmasq 已重载",
            evidence=f"file={payload.config_path},process={payload.resolver_process}",
        )


class RevertContractTest(unittest.TestCase):
    """「30 分钟内可一键撤销」的契约测试"""

    def setUp(self) -> None:
        self.enforcer = FakeDnsBlackholeEnforcer()

    # ── 1. Happy path：apply → payload 齐全 → revert → 核验通过 ──
    def test_1_happy_path_round_trip(self):  # P1 / P3
        action = EnforceAction.create("act-1", "domain", "api.ad.tuya.com", now=T0)
        result = self.enforcer.apply(action)

        self.assertTrue(result.ok)
        # P1：payload 必须是结构化子类，不是 dict
        self.assertIsInstance(action.revert_payload, DnsBlackholePayload)
        self.assertNotIsInstance(action.revert_payload, dict)
        self.assertEqual(action.revert_payload.kind, "dns_blackhole")
        self.assertTrue(action.revert_payload.is_complete())
        # 契约校验（apply 后必检）
        self.assertTrue(validate_applied(action, result))
        assert_revert_contract(action, result)  # 不抛异常即通过

        reverted = self.enforcer.revert_and_verify(action, now=T0 + 60)
        self.assertTrue(reverted.ok)
        self.assertTrue(reverted.verified, "P3：撤销后必须核验通过才算真的撤销")
        self.assertTrue(reverted.fully_reverted)
        self.assertFalse(reverted.requires_manual)
        self.assertFalse(self.enforcer.config_contains("address=/api.ad.tuya.com/0.0.0.0"))

    # ── 2. 契约强制：apply 成功却没留下可用 payload → 判失败 ──
    def test_2_contract_enforced(self):  # P1
        lying = FakeDnsBlackholeEnforcer(emit_payload=False)
        action = EnforceAction.create("act-2", "domain", "tracker.example.com", now=T0)
        result = lying.apply(action)

        self.assertTrue(result.ok, "规则确实生效了")
        self.assertIsNone(action.revert_payload)
        self.assertFalse(validate_applied(action, result))
        with self.assertRaises(RevertContractError):
            assert_revert_contract(action, result)
        # 且撤销入口拒绝动手，而不是"假装撤销"
        reverted = lying.revert_and_verify(action, now=T0 + 10)
        self.assertFalse(reverted.ok)
        self.assertFalse(reverted.verified)
        self.assertIn("revert_payload", reverted.message)

        # payload 存在但字段不全（没有备份、没有重载命令）同样判失败
        partial = EnforceAction.create("act-2b", "domain", "ads.example.com", now=T0)
        self.enforcer.apply(partial)
        partial.revert_payload.entry = ""
        self.assertFalse(partial.revert_payload.is_complete())
        self.assertFalse(validate_applied(partial, EnforceResult(True, "act-2b")))

    # ── 3. 幂等：同一 action 连续撤销两次仍 ok + verified，不抛异常 ──
    def test_3_idempotent(self):  # P3
        action = EnforceAction.create("act-3", "domain", "log.example.com", now=T0)
        self.enforcer.apply(action)

        first = self.enforcer.revert_and_verify(action, now=T0 + 30)
        second = self.enforcer.revert_and_verify(action, now=T0 + 31)
        self.assertTrue(first.ok and first.verified)
        self.assertTrue(second.ok, "重复撤销不得报错")
        self.assertTrue(second.verified, "已无规则的稳定状态应核验通过")
        self.assertEqual(self.enforcer.revert_calls, 2)
        # 直接调 revert 两次也不许抛
        self.enforcer.revert(action)
        self.enforcer.revert(action)

    # ── 4. 超出一键窗口：规则仍在生效，force_revert 仍能解封 ──
    def test_4_window_expired_still_recoverable(self):  # P4 / P5
        action = EnforceAction.create("act-4", "domain", "cam.example.com", now=T0)
        self.enforcer.apply(action)
        entry = action.revert_payload.entry
        late = T0 + REDEEM_WINDOW_SECONDS + 60  # 窗口已过

        self.assertFalse(action.is_redeemable(late))
        self.assertEqual(action.revert_mode(late), "manual")
        self.assertTrue(action.is_in_effect(late), "P4：窗口过期**不解除规则**")

        one_click = self.enforcer.revert_and_verify(action, now=late)
        self.assertFalse(one_click.ok)
        self.assertTrue(one_click.requires_manual, "P5：必须明确告知走人工通道")
        self.assertFalse(one_click.verified)
        self.assertTrue(self.enforcer.config_contains(entry), "未获授权时不得擅自改动规则")

        forced = self.enforcer.revert_and_verify(action, now=late, force=True)
        self.assertTrue(forced.ok, "P5：人工通道必须真能解封")
        self.assertTrue(forced.verified)
        self.assertTrue(forced.requires_manual, "人工通道需被标记以便审计")
        self.assertFalse(self.enforcer.config_contains(entry))

    # ── 5. 撤销"成功"但核验失败：必须显式暴露，不能静默 ──
    def test_5_verify_failure_is_loud(self):  # P3
        # 5a：回滚指令成功，但配置条目没真删掉
        sabotaged = FakeDnsBlackholeEnforcer(sabotage_removal=True)
        action = EnforceAction.create("act-5a", "domain", "spy.example.com", now=T0)
        sabotaged.apply(action)
        result = sabotaged.revert_and_verify(action, now=T0 + 10)

        self.assertTrue(result.ok, "底层返回成功")
        self.assertFalse(result.verified, "P3：绝不能把 ok 当成 verified")
        self.assertFalse(result.fully_reverted)
        self.assertIn("核验未通过", result.message)
        self.assertTrue(sabotaged.config_contains(action.revert_payload.entry))
        self.assertFalse(sabotaged.verify_revert(action).verified)

        # 5b：条目删了但进程没重载 —— 另一类假恢复
        no_reload = FakeDnsBlackholeEnforcer(sabotage_reload=True)
        action_b = EnforceAction.create("act-5b", "domain", "metrics.example.com", now=T0)
        no_reload.apply(action_b)
        result_b = no_reload.revert_and_verify(action_b, now=T0 + 10)
        self.assertTrue(result_b.ok)
        self.assertFalse(result_b.verified)
        self.assertIn("未重载", result_b.message)

        # 自相矛盾的结果不允许构造
        with self.assertRaises(ValueError):
            RevertResult(ok=False, verified=True)

    # ── 6. 时间语义分离：auto_release_at=None = 持久生效 ──
    def test_6_time_semantics_split(self):  # P4
        action = EnforceAction.create("act-6", "domain", "tv.example.com", now=T0)
        self.assertIsNone(action.auto_release_at)
        self.assertTrue(action.is_persistent())
        # 一万年之后也不能被当成"自动解除"
        far_future = T0 + 86400 * 3650
        self.assertFalse(action.is_released(far_future))
        self.assertTrue(action.is_in_effect(far_future))
        # 一键窗口确实是 30 分钟
        self.assertTrue(action.is_redeemable(T0 + REDEEM_WINDOW_SECONDS - 1))
        self.assertFalse(action.is_redeemable(T0 + REDEEM_WINDOW_SECONDS + 1))

        # 反向：显式声明 auto_release_at 的规则到点解除，且不再需要撤销
        timed = EnforceAction(
            action_id="act-6b",
            scope="domain",
            target="speaker.example.com",
            applied_at=T0,
            redeemable_until=T0 + 600,
            auto_release_at=T0 + 3600,
        )
        self.assertFalse(timed.is_persistent())
        self.assertTrue(timed.is_released(T0 + 3601))
        self.assertEqual(timed.revert_mode(T0 + 3601), "released")

        # 易被误读的组合必须被拒绝：按钮有效期晚于规则有效期
        with self.assertRaises(ValueError):
            EnforceAction(
                action_id="act-6c",
                scope="domain",
                target="bad.example.com",
                applied_at=T0,
                redeemable_until=T0 + 7200,
                auto_release_at=T0 + 3600,
            )

    # ── 7. 规则已自动解除时：撤销退化为幂等核验，不该把用户赶到人工通道 ──
    def test_7_auto_released_is_not_manual(self):  # P4 / P5
        action = EnforceAction(
            action_id="act-8",
            scope="domain",
            target="sensor.example.com",
            applied_at=T0,
            redeemable_until=T0 + 600,
            auto_release_at=T0 + 3600,
        )
        self.enforcer.apply(action)
        self.enforcer.revert(action)  # 模拟调度器在 auto_release_at 到点做的清理

        after_release = T0 + 3601
        self.assertEqual(action.revert_mode(after_release), "released")
        result = self.enforcer.revert_and_verify(action, now=after_release)
        self.assertTrue(result.ok)
        self.assertTrue(result.verified, "规则已自动解除，状态应当确认是放行的")
        self.assertFalse(result.requires_manual, "自动解除不该把用户赶到人工通道")
        self.assertIn("自动解除", result.message)

    # ── 8. 注册表：UI 只持有 action_id 也能完成撤销 ──
    def test_8_registry_revert_by_id(self):  # P2
        registry = ActionRegistry()
        action = EnforceAction.create("act-7", "domain", "plug.example.com", now=T0)
        self.enforcer.apply(action)
        registry.save(action)

        self.assertIn("act-7", registry)
        self.assertEqual(len(registry), 1)
        self.assertEqual(len(registry.redeemable(T0 + 10)), 1)

        result = registry.revert_with(self.enforcer, "act-7", now=T0 + 10)
        self.assertTrue(result.ok and result.verified, "P2：只凭 id 也要能撤销")
        self.assertEqual(result.action_id, "act-7")

        missing = registry.revert_with(self.enforcer, "act-nope", now=T0 + 10)
        self.assertFalse(missing.ok)
        self.assertIn("未找到", missing.message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
