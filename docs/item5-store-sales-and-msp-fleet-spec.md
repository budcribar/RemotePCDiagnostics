# Item 5 & 6B Specification: Multi-Tenant MSP Unattended Fleet Scoping (`AgentHub` / `AgentAdmin`) & `/shop` Fleet Portal

> Mirror summary of [`RemoteBlazorWebView/doc/ShopMspFleetAndAgentScopingSpec.md`](https://github.com/budcribar/RemoteBlazorWebView/blob/net10/doc/ShopMspFleetAndAgentScopingSpec.md) for cross-repo tracking in `RemotePCDiagnostics`.

**Target Repository:** `budcribar/RemoteBlazorWebView`  
**Target Branch:** `net10`  
**Baseline Commit:** `924d5cf` (`Add the shop welcome page, demo certificate, and relay hardening`)  
**Scope Constraint:** Work **strictly inside `RemoteBlazorWebView`**. Do **not** modify `budcribar/RemotePCDiagnostics`.

---

## Summary of Deliverables for Parallel Bot #2

1. **Wire-Compatible `agent.proto` `group` Field:**
   - Add `string group = 6;` to `LaunchCommand` and `string group = 14;` to `AgentInfo` so fleet-launched sessions pass `-g=<group>` to `RemotePCDiagnostics.Host.exe`.
2. **`IAgentTenantPolicy` + Multi-Tenant `AgentRegistry` Isolation:**
   - Keep `RemoteWebViewService.Lib` 100% Native AOT compatible via `IAgentTenantPolicy` (`AllowAllAgentTenantPolicy` default).
   - Scope `AgentRegistry` (`Register`, `GetAgentList`, `StartSession`, `SubscribeLaunch`, `CancelLaunch`) by `groupScope` so MSP Tenant A can never view, start, watch, or cancel MSP Tenant B's fleet machines.
3. **`ShopAgentTenantPolicy` & `/shop` Fleet Computers Portal:**
   - Authenticate `AgentHello.EnrollmentKey` (`rpd_live_...`) against active `"msp"` `ShopTenants`, rejecting Solo/Shop or inactive keys with `PermissionDenied`.
   - Render the **Fleet Computers** table, `POST /shop/computers/{machineId}/start` 1-click remote session launcher, and copy-paste **RMM PowerShell Install Snippet** on `/shop` for `"msp"` tenants.
4. **Integration Tests (`ShopIdentityTests.cs`):**
   - MSP plan gate on `AgentHub.Connect`, cross-tenant isolation (`msp-alpha` vs `msp-beta`), and `LaunchCommand.Group` verification.
