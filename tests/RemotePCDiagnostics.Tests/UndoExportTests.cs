using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Tests;

public class UndoExportTests
{
    private static ChangeRecord Change(ChangeKind kind, string label, bool restart = false) =>
        ChangeRecord.New(kind, "target", null, label, "Technician", restart);

    [Fact]
    public void Undo_copy_lists_each_change_with_the_id_its_button_uses()
    {
        var startup = Change(ChangeKind.StartupApp, "Turned off OneDrive at startup");
        var update = Change(ChangeKind.NotUndoable, "Installed KB5050001");

        using var doc = JsonDocument.Parse(AgentExports.Undo(true, [startup], [update], false, 0, null, null));
        var root = doc.RootElement;

        Assert.True(root.GetProperty("loaded").GetBoolean());
        Assert.False(root.GetProperty("busy").GetBoolean());
        var pending = Assert.Single(root.GetProperty("pending").EnumerateArray());
        Assert.Equal(startup.Id.ToString(), pending.GetProperty("id").GetString());
        Assert.Equal("StartupApp", pending.GetProperty("kind").GetString());
        Assert.Equal("Installed KB5050001", Assert.Single(root.GetProperty("permanent").EnumerateArray()).GetProperty("label").GetString());
        Assert.False(root.TryGetProperty("lastResult", out _));
    }

    [Fact]
    public void Undo_copy_reports_the_last_result_with_a_sequence_number()
    {
        var page = Change(ChangeKind.PageFile, "Page file size", restart: true);
        var one = new UndoItemResult(page, true, "Put back.");

        using var doc = JsonDocument.Parse(AgentExports.Undo(true, [], [], false, 3, null, one));
        var result = doc.RootElement.GetProperty("lastResult");

        Assert.Equal(3, doc.RootElement.GetProperty("resultSeq").GetInt32());
        Assert.Equal("one", result.GetProperty("kind").GetString());
        Assert.Equal(1, result.GetProperty("succeeded").GetInt32());
        Assert.True(result.GetProperty("needsRestart").GetBoolean());
        Assert.Equal("undone", Assert.Single(result.GetProperty("items").EnumerateArray()).GetProperty("outcome").GetString());

        var all = new UndoAllResult([one, new UndoItemResult(Change(ChangeKind.NotUndoable, "Removed app"), false, "Permanent", Skipped: true)]);
        using var allDoc = JsonDocument.Parse(AgentExports.Undo(true, [], [], false, 4, all, null));
        var allResult = allDoc.RootElement.GetProperty("lastResult");
        Assert.Equal("all", allResult.GetProperty("kind").GetString());
        Assert.Equal(1, allResult.GetProperty("skipped").GetInt32());
        Assert.Equal(all.Summary, allResult.GetProperty("summary").GetString());
    }
}
