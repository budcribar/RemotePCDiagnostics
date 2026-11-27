using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Input;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

/// <summary>A hand-driven clock for the pointer test's timeouts and input windows.</summary>
internal sealed class ManualClock(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>A stand-in for Windows raw input: the test says what the hardware did.</summary>
internal sealed class FakePhysicalInput(params PointerDevice[] devices) : IPhysicalInputMonitor
{
    public string? UnavailableReason { get; set; }
    public int Leases { get; private set; }
    public IReadOnlyList<PointerDevice> PointerDevices() => devices;
    public event Action<PhysicalInputEvent>? Input;
    public IDisposable Listen()
    {
        Leases++;
        return new Lease(this);
    }
    public void Send(PhysicalInputEvent e) => Input?.Invoke(e);
    private sealed class Lease(FakePhysicalInput owner) : IDisposable
    {
        public void Dispose() => owner.Leases--;
    }
}

public class PointerTestTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 27, 21, 0, 0, TimeSpan.Zero);
    private static readonly PointerDevice Mouse = new("USB\\VID_046D&PID_C52B\\1", "Logitech USB Receiver", PointerDeviceKind.Mouse);
    private static readonly PointerDevice Pad = new("ACPI\\ELAN0001\\1", "ELAN touchpad", PointerDeviceKind.Touchpad, PrecisionTouchpad: true);
    private static readonly PointerDevice Screen = new("HID\\WACOM\\1", "Wacom touch", PointerDeviceKind.Touchscreen);

    private static (PointerTestService Test, FakePhysicalInput Hw, ManualClock Clock) New(params PointerDevice[] devices)
    {
        var clock = new ManualClock(T0);
        var hw = new FakePhysicalInput(devices.Length == 0 ? [Mouse] : devices);
        return (new PointerTestService(hw, clock, TimeSpan.Zero), hw, clock);
    }

    private static PhysicalInputEvent Hw(ManualClock c, PhysicalInputKind kind, PointerDevice d, PointerButton? button = null, int value = 0) =>
        new(c.Now, kind, d.Id, d.Kind, false, button, value);

    private static async Task DoubleClick(PointerTestService t, FakePhysicalInput hw, ManualClock c, PointerButton b, PointerDevice d)
    {
        for (var i = 0; i < 2; i++)
        {
            hw.Send(Hw(c, PhysicalInputKind.ButtonDown, d, b));
            await t.ButtonDownAsync(b);
            c.Advance(TimeSpan.FromMilliseconds(120));
        }
    }

    [Fact]
    public async Task A_mouse_passes_when_every_step_is_done_on_the_hardware()
    {
        var (t, hw, c) = New();
        t.Start(Mouse);
        Assert.Equal([PointerStep.Move, PointerStep.Buttons, PointerStep.Scroll, PointerStep.Drag], t.Current.Steps.Select(s => s.Step));
        Assert.Equal(1, hw.Leases);

        for (var corner = 0; corner < 4; corner++)
        {
            hw.Send(Hw(c, PhysicalInputKind.Move, Mouse));
            await t.CornerAsync(corner);
        }
        Assert.Equal(PointerStep.Buttons, t.Current.Current);

        await DoubleClick(t, hw, c, PointerButton.Left, Mouse);
        await DoubleClick(t, hw, c, PointerButton.Right, Mouse);
        await DoubleClick(t, hw, c, PointerButton.Middle, Mouse);
        Assert.Equal(PointerStep.Scroll, t.Current.Current);

        for (var i = 0; i < 3; i++)
        {
            hw.Send(Hw(c, PhysicalInputKind.Wheel, Mouse, value: 1));
            await t.ScrollAsync(0, -100);
            hw.Send(Hw(c, PhysicalInputKind.Wheel, Mouse, value: -1));
            await t.ScrollAsync(0, 100);
        }
        Assert.Equal(6, t.Current.WheelTicks);
        Assert.Equal(PointerStep.Drag, t.Current.Current);

        foreach (var b in new[] { PointerButton.Left, PointerButton.Right })
        {
            hw.Send(Hw(c, PhysicalInputKind.ButtonDown, Mouse, b));
            await t.ButtonDownAsync(b);
            hw.Send(Hw(c, PhysicalInputKind.Move, Mouse));
            await t.DropAsync(b, b);
        }

        var done = t.Current;
        Assert.Equal(PointerTestVerdict.Passed, done.Verdict);
        Assert.All(done.Steps, s => Assert.Equal(PointerStepState.Passed, s.State));
        Assert.Equal(0, done.IgnoredInputs);
        Assert.True(done.InputVerified);
        Assert.Equal(0, hw.Leases);
    }

    [Fact]
    public async Task Clicks_and_moves_with_no_hardware_input_behind_them_do_not_count()
    {
        // A remote technician's browser input reaches the page but never Windows.
        var (t, hw, c) = New();
        t.Start(Mouse);
        for (var corner = 0; corner < 4; corner++) await t.CornerAsync(corner);
        Assert.Equal(0, t.Current.CornerCount);
        Assert.Equal(4, t.Current.IgnoredInputs);

        // Injected input (SendInput, Remote Desktop) doesn't count either.
        hw.Send(new PhysicalInputEvent(c.Now, PhysicalInputKind.Move, Injected: true));
        hw.Send(new PhysicalInputEvent(c.Now, PhysicalInputKind.ButtonDown, Injected: true, Button: PointerButton.Left));
        await t.CornerAsync(0);
        Assert.Equal(0, t.Current.CornerCount);
        Assert.Equal(1, t.Current.InjectedInputs);
        Assert.Equal(PointerStep.Move, t.Current.Current);
    }

    [Fact]
    public async Task Only_the_chosen_device_counts_and_one_press_backs_one_click()
    {
        var other = new PointerDevice("USB\\OTHER", "Other mouse", PointerDeviceKind.Mouse);
        var (t, hw, c) = New(Mouse, other);
        t.Start(Mouse);
        hw.Send(Hw(c, PhysicalInputKind.Move, other));
        await t.CornerAsync(0);
        Assert.Equal(0, t.Current.CornerCount);

        t.Skip();
        Assert.Equal(PointerStep.Buttons, t.Current.Current);
        // One hardware click can't stand for both clicks of a double-click.
        hw.Send(Hw(c, PhysicalInputKind.ButtonDown, Mouse, PointerButton.Left));
        await t.ButtonDownAsync(PointerButton.Left);
        await t.ButtonDownAsync(PointerButton.Left);
        Assert.False(t.Current.LeftDoubleClick);
        // Nor can a press of another button.
        hw.Send(Hw(c, PhysicalInputKind.ButtonDown, Mouse, PointerButton.Right));
        await t.ButtonDownAsync(PointerButton.Left);
        Assert.False(t.Current.LeftDoubleClick);
    }

    [Fact]
    public async Task Hardware_input_older_than_the_window_does_not_count()
    {
        var (t, hw, c) = New();
        t.Start(Mouse);
        hw.Send(Hw(c, PhysicalInputKind.Move, Mouse));
        c.Advance(PhysicalInputGate.Window + TimeSpan.FromMilliseconds(1));
        await t.CornerAsync(0);
        Assert.Equal(0, t.Current.CornerCount);
    }

    [Fact]
    public async Task A_step_with_no_input_for_30_seconds_fails_and_the_test_fails()
    {
        var (t, hw, c) = New();
        t.Start(Mouse);
        c.Advance(TimeSpan.FromSeconds(10));
        t.Tick();
        Assert.Equal(20, t.Current.SecondsLeft);

        // Input restarts the 30 seconds.
        hw.Send(Hw(c, PhysicalInputKind.Move, Mouse));
        await t.CornerAsync(1);
        c.Advance(TimeSpan.FromSeconds(29));
        t.Tick();
        Assert.Equal(PointerStep.Move, t.Current.Current);
        c.Advance(TimeSpan.FromSeconds(1));
        t.Tick();
        Assert.Equal(PointerStepState.Failed, t.Current.StateOf(PointerStep.Move));
        Assert.Equal("No input for 30 seconds.", t.Current.Steps[0].Reason);
        Assert.Equal(PointerStep.Buttons, t.Current.Current);

        t.Skip();
        t.FailStep();
        t.Skip();
        var done = t.Current;
        Assert.Equal(PointerTestVerdict.Failed, done.Verdict);
        Assert.Equal([PointerStepState.Failed, PointerStepState.Skipped, PointerStepState.Failed, PointerStepState.Skipped], done.Steps.Select(s => s.State));
        Assert.Equal("The person said it doesn't work.", done.Steps[2].Reason);
    }

    [Fact]
    public void Skipping_every_step_is_skipped_not_passed()
    {
        var (t, _, _) = New();
        t.Start(Mouse);
        for (var i = 0; i < 4; i++) t.Skip();
        Assert.Equal(PointerTestVerdict.Skipped, t.Current.Verdict);
    }

    [Fact]
    public async Task No_middle_button_still_passes_the_buttons_step()
    {
        var (t, hw, c) = New();
        t.Start(Mouse);
        t.Skip();
        await DoubleClick(t, hw, c, PointerButton.Left, Mouse);
        await DoubleClick(t, hw, c, PointerButton.Right, Mouse);
        Assert.Equal(PointerStep.Buttons, t.Current.Current);
        t.SetNoMiddleButton(true);
        Assert.Equal(PointerStepState.Passed, t.Current.StateOf(PointerStep.Buttons));
    }

    [Fact]
    public async Task Clicks_further_apart_than_the_double_click_time_are_not_a_double_click()
    {
        var (t, hw, c) = New();
        t.Start(Mouse);
        t.Skip();
        hw.Send(Hw(c, PhysicalInputKind.ButtonDown, Mouse, PointerButton.Left));
        await t.ButtonDownAsync(PointerButton.Left);
        c.Advance(TimeSpan.FromMilliseconds(600));
        hw.Send(Hw(c, PhysicalInputKind.ButtonDown, Mouse, PointerButton.Left));
        await t.ButtonDownAsync(PointerButton.Left);
        Assert.False(t.Current.LeftDoubleClick);
    }

    [Fact]
    public async Task A_precision_touchpad_adds_taps_two_finger_click_and_three_fingers()
    {
        var (t, hw, c) = New(Pad);
        t.Start(Pad);
        Assert.Equal(PointerStep.TouchpadGestures, t.Current.Steps[^1].Step);
        for (var i = 0; i < 4; i++) t.Skip();
        Assert.Equal(PointerStep.TouchpadGestures, t.Current.Current);

        // A press of the touchpad is a click, not a tap.
        hw.Send(Hw(c, PhysicalInputKind.Contacts, Pad, value: 1));
        hw.Send(Hw(c, PhysicalInputKind.ButtonDown, Pad, PointerButton.Left));
        await t.ButtonDownAsync(PointerButton.Left);
        Assert.False(t.Current.TapToClick);

        c.Advance(TimeSpan.FromSeconds(1));
        hw.Send(Hw(c, PhysicalInputKind.Contacts, Pad, value: 1));
        await t.ButtonDownAsync(PointerButton.Left);
        Assert.True(t.Current.TapToClick);

        // A right click from one finger (a corner press) is not a two-finger click.
        await t.ButtonDownAsync(PointerButton.Right);
        Assert.False(t.Current.TwoFingerClick);
        hw.Send(Hw(c, PhysicalInputKind.Contacts, Pad, value: 2));
        await t.ButtonDownAsync(PointerButton.Right);
        Assert.True(t.Current.TwoFingerClick);

        hw.Send(Hw(c, PhysicalInputKind.Contacts, Pad, value: 4));
        Assert.Equal(4, t.Current.MaxTouchpadContacts);
        Assert.Equal(PointerStepState.Passed, t.Current.StateOf(PointerStep.TouchpadGestures));
        Assert.Equal(PointerTestVerdict.Passed, t.Current.Verdict);
    }

    [Fact]
    public async Task Two_finger_scrolling_on_a_touchpad_counts_without_wheel_notches()
    {
        var (t, hw, c) = New(Pad);
        t.Start(Pad);
        t.Skip();
        t.Skip();
        for (var i = 0; i < 3; i++)
        {
            hw.Send(Hw(c, PhysicalInputKind.Contacts, Pad, value: 2));
            await t.ScrollAsync(0, -40);
            await t.ScrollAsync(0, 40);
        }
        Assert.Equal(PointerStepState.Passed, t.Current.StateOf(PointerStep.Scroll));
        Assert.Equal(0, t.Current.WheelTicks);
    }

    [Fact]
    public async Task A_touchscreen_passes_when_every_square_is_touched_and_reports_its_touch_points()
    {
        var (t, hw, c) = New(Screen);
        t.Start(Screen);
        Assert.Equal([PointerStep.TouchGrid], t.Current.Steps.Select(s => s.Step));
        const double w = 1200, h = 800;

        // Five touches on the page but Windows saw only two: two count.
        hw.Send(Hw(c, PhysicalInputKind.Contacts, Screen, value: 2));
        await t.TouchAsync(10, 10, w, h, contacts: 5);
        Assert.Equal(2, t.Current.MaxTouchPoints);

        for (var row = 0; row < PointerTestService.GridRows; row++)
            for (var col = 0; col < PointerTestService.GridColumns; col++)
            {
                if (row == 3 && col == 5) continue;
                hw.Send(Hw(c, PhysicalInputKind.Contacts, Screen, value: 1));
                await t.TouchAsync(col * 200 + 100, row * 200 + 100, w, h, 1);
            }
        Assert.Equal(23, t.Current.CellsTouched.Count);
        Assert.Equal(PointerTestVerdict.Running, t.Current.Verdict);

        // A dead corner: the person gives up on it.
        c.Advance(TimeSpan.FromSeconds(30));
        t.Tick();
        Assert.Equal(PointerTestVerdict.Failed, t.Current.Verdict);

        var page = new InteractiveExport.PageState("pointer", ["pointer"], false, false, false, false);
        using var doc = JsonDocument.Parse(InteractiveExport.ToJson(page, new PhysicalBenchQaSnapshot(), NotRun("Webcam"), NotRun("SpeakerToMic"),
            NotRun("MicToSpeaker"), pointer: t.Current));
        var ptr = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "pointer");
        Assert.Equal("failed", ptr.GetProperty("verdict").GetString());
        Assert.Equal([23], ptr.GetProperty("measured").GetProperty("untouchedCells").EnumerateArray().Select(e => e.GetInt32()));
        Assert.Equal("touchscreen", ptr.GetProperty("device").GetProperty("kind").GetString());
        Assert.Equal("touch-grid", ptr.GetProperty("steps")[0].GetProperty("id").GetString());
        Assert.Equal("No input for 30 seconds.", ptr.GetProperty("steps")[0].GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Without_verification_input_counts_locally_but_never_during_a_remote_session()
    {
        var (t, hw, _) = New();
        hw.UnavailableReason = "Input can't be checked on this computer.";
        t.Start(Pad);
        Assert.Equal(PointerStepState.NotSupported, t.Current.StateOf(PointerStep.TouchpadGestures));
        Assert.False(t.Current.InputVerified);

        await t.CornerAsync(0);
        Assert.Equal(1, t.Current.CornerCount);

        t.RemoteSessionActive = true;
        await t.CornerAsync(1);
        Assert.Equal(1, t.Current.CornerCount);
        Assert.Equal(1, t.Current.IgnoredInputs);
    }

    [Fact]
    public void Steps_depend_on_the_device()
    {
        Assert.Equal(4, PointerTestService.StepsFor(Mouse).Count);
        Assert.Equal(4, PointerTestService.StepsFor(Pad with { PrecisionTouchpad = false }).Count);
        Assert.Equal(5, PointerTestService.StepsFor(Pad).Count);
        Assert.Equal([PointerStep.TouchGrid], PointerTestService.StepsFor(Screen));
        Assert.Equal([PointerStep.Move, PointerStep.TouchGrid], PointerTestService.StepsFor(Screen with { Kind = PointerDeviceKind.Pen }));
    }

    [Fact]
    public async Task Stopping_keeps_the_steps_done_and_stops_listening()
    {
        var (t, hw, c) = New();
        t.Start(Mouse);
        hw.Send(Hw(c, PhysicalInputKind.Move, Mouse));
        await t.CornerAsync(2);
        t.Cancel();
        Assert.Equal(PointerTestVerdict.Cancelled, t.Current.Verdict);
        Assert.Equal(1, t.Current.CornerCount);
        Assert.Null(t.Current.Current);
        Assert.Equal(0, hw.Leases);
    }

    [Fact]
    public void With_no_devices_reported_the_picker_offers_one_unnamed_pointer()
    {
        var t = new PointerTestService(new UnavailablePhysicalInputMonitor("no"));
        var only = Assert.Single(t.Devices());
        Assert.Equal("", only.Id);
        Assert.Equal(PointerDeviceKind.Mouse, only.Kind);
    }

    [Fact]
    public void A_touchpad_press_backs_a_right_click_and_contacts_back_a_touch_tap()
    {
        var press = new PhysicalInputEvent(T0, PhysicalInputKind.ButtonDown, Pad.Id, PointerDeviceKind.Touchpad, Button: PointerButton.Left);
        Assert.True(PhysicalInputGate.Matches(press, PhysicalInputKind.ButtonDown, PointerButton.Right, 1));
        var mouseLeft = press with { DeviceKind = PointerDeviceKind.Mouse };
        Assert.False(PhysicalInputGate.Matches(mouseLeft, PhysicalInputKind.ButtonDown, PointerButton.Right, 1));
        var touch = new PhysicalInputEvent(T0, PhysicalInputKind.Contacts, Screen.Id, PointerDeviceKind.Touchscreen, Value: 1);
        Assert.True(PhysicalInputGate.Matches(touch, PhysicalInputKind.ButtonDown, PointerButton.Left, 1));
        Assert.False(PhysicalInputGate.Matches(touch, PhysicalInputKind.Key, null, 1));
    }

    [Fact]
    public void Keyboard_export_reports_keys_not_counted()
    {
        var page = new InteractiveExport.PageState("keyboard", ["keyboard"], false, false, true, false);
        var bench = new PhysicalBenchQaSnapshot(UniqueKeysPressed: 3, IgnoredKeys: 7, KeysVerified: true);
        using var doc = JsonDocument.Parse(InteractiveExport.ToJson(page, bench, NotRun("Webcam"), NotRun("SpeakerToMic"), NotRun("MicToSpeaker")));
        var measured = doc.RootElement.GetProperty("tests")[0].GetProperty("measured");
        Assert.Equal(7, measured.GetProperty("ignoredKeys").GetInt32());
        Assert.True(measured.GetProperty("keysVerified").GetBoolean());
        var ptr = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "pointer");
        Assert.Equal("waiting-for-person", ptr.GetProperty("state").GetString());
        Assert.Equal("notrun", ptr.GetProperty("verdict").GetString());
    }

    private static InteractiveExport.ModuleState NotRun(string slug) => new(new DiagnosticResult(slug, DiagnosticStatus.NotRun, "", T0), false);
}

/// <summary>The Pointer and touch pane and the Keyboard pane on the Interactive tests page.</summary>
public class PointerTestPageTests : BunitContext
{
    private static readonly PointerDevice Mouse = new("USB\\VID_046D\\1", "Logitech USB Receiver", PointerDeviceKind.Mouse);

    private IRenderedComponent<InteractiveTestsPage> Render(FakePhysicalInput hw, PointerTestService pointer, PhysicalBenchQaService bench, string test)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var store = new ResultStore();
        var diagnostics = new DiagnosticsService(store, []);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new ChecksScreenState(diagnostics, store));
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(PhysicalQa: bench, PhysicalInput: hw, PointerTest: pointer));
        Services.GetRequiredService<NavigationManager>().NavigateTo("interactive?test=" + test);
        return Render<InteractiveTestsPage>();
    }

    [Fact]
    public void The_pointer_row_opens_a_pane_that_lists_the_devices_and_runs_the_steps()
    {
        var hw = new FakePhysicalInput(Mouse);
        var pointer = new PointerTestService(hw, grace: TimeSpan.Zero);
        var page = Render(hw, pointer, new PhysicalBenchQaService(), "pointer");

        Assert.NotNull(page.Find("[data-testid='interactive-row-pointer']"));
        Assert.Contains("Logitech USB Receiver (mouse)", page.Find("[data-testid='pointer-device-select']").TextContent);
        page.Find("[data-testid='pointer-start']").Click();
        page.WaitForAssertion(() => Assert.NotNull(page.Find("[data-testid='pointer-overlay']")));
        Assert.Equal(4, page.FindAll(".ptr-corner").Count);

        // A corner reached in the browser with no hardware movement doesn't count.
        page.Find("[data-testid='pointer-corner-0']").TriggerEvent("onpointerenter", new PointerEventArgs());
        page.WaitForAssertion(() => Assert.Equal("1", page.Find("[data-testid='pointer-ignored']").TextContent));

        hw.Send(new PhysicalInputEvent(DateTimeOffset.UtcNow, PhysicalInputKind.Move, Mouse.Id, PointerDeviceKind.Mouse));
        page.Find("[data-testid='pointer-corner-0']").TriggerEvent("onpointerenter", new PointerEventArgs());
        page.WaitForAssertion(() => Assert.Contains("ptr-hit", page.Find("[data-testid='pointer-corner-0']").ClassName));

        var json = page.Find("[data-testid='interactive-data']").GetAttribute("data-report")!;
        using var doc = JsonDocument.Parse(json);
        var ptr = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "pointer");
        Assert.Equal("running", ptr.GetProperty("state").GetString());
        Assert.Equal("move", ptr.GetProperty("currentStep").GetString());
        Assert.Equal(1, ptr.GetProperty("measured").GetProperty("corners").GetInt32());

        page.Find("[data-testid='pointer-overlay-stop']").Click();
        page.WaitForAssertion(() => Assert.Empty(page.FindAll("[data-testid='pointer-overlay']")));
        Assert.Equal("Stopped", page.Find("[data-testid='interactive-status-pointer']").TextContent.Trim());
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "pointer-pane.html"), page.Markup);
    }

    [Fact]
    public void Keys_the_keyboard_did_not_press_are_not_counted()
    {
        var hw = new FakePhysicalInput(Mouse);
        var bench = new PhysicalBenchQaService();
        var page = Render(hw, new PointerTestService(hw), bench, "keyboard");
        var zone = page.Find("[data-testid='keyboard-test-zone']");

        // The remote viewer's key: the page sees it, Windows doesn't.
        zone.KeyDown(new KeyboardEventArgs { Code = "KeyA", Key = "a" });
        page.WaitForAssertion(() => Assert.Equal(1, bench.Current.IgnoredKeys), TimeSpan.FromSeconds(3));
        Assert.Equal(0, bench.Current.UniqueKeysPressed);

        hw.Send(new PhysicalInputEvent(DateTimeOffset.UtcNow, PhysicalInputKind.Key));
        zone.KeyDown(new KeyboardEventArgs { Code = "KeyB", Key = "b" });
        page.WaitForAssertion(() => Assert.Equal(1, bench.Current.UniqueKeysPressed), TimeSpan.FromSeconds(3));
        Assert.True(bench.Current.KeysVerified);
        Assert.Contains("not counted", page.Find("[data-testid='interactive-keyboard-pane']").TextContent);
    }
}
