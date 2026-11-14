# Extending the keyboard test

The keyboard test under **Interactive Tests** draws an SVG from the selected candidate. The application reads the tested Windows PC's manufacturer, product name, family, system SKU, and configured input language. A model rule ranks the deck with or without a physical numpad first. An exact regional SKU can take precedence over the input language. The user can select any candidate.

## Add a model mapping

1. Check the manufacturer's manual or spec sheet for the exact chassis or SKU. Record the source and whether the keyboard has a separate physical numpad. A touchpad NumberPad does not use the physical numpad template.
2. In [KeyboardLayout.cs](../src/RemotePCDiagnostics.UI/Shared/KeyboardLayout.cs), add the manufacturer and model pattern to **ModelRules**, or extend an existing rule with the same deck preference. Match the identifiers Windows reports. You can read them on the tested PC with PowerShell:

   ~~~powershell
   Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS' |
       Select-Object SystemManufacturer, SystemProductName, SystemFamily, SystemSKU
   ~~~

3. Use narrow patterns when identifiers overlap across product lines or generations. Matching ignores case and treats underscores as separators. Use a documented exact SKU to rank regional legends only when the source specifies the shipped keyboard.
4. Add a test case with a representative firmware string and another for a similar model that should fall back.

## Add a layout

1. Add a stable candidate ID and display name in **GetCandidates**. Each candidate currently expands into compact and numpad variants.
2. Use **Legend** for printed labels. Keep the key's **KeyboardEvent.code** tied to its physical position so highlighting works across regional layouts.
3. Use **Create** and **KeyWidth** for geometry changes. Include additional physical keys where appropriate and check the SVG view box in **PhysicalBenchQaCard.razor** if the layout needs more space.
4. Extend **KeyboardLayoutTests** with the new candidate count and assertions for its distinctive key positions or legends. In the app, select both variants, capture keys, and confirm the expected caps highlight while testing rollover.

Run the mapping and interactive QA tests from the repository root:

~~~powershell
dotnet test tests/RemotePCDiagnostics.Tests --filter 'FullyQualifiedName~KeyboardLayoutTests|FullyQualifiedName~InteractiveTestsTests|FullyQualifiedName~BenchQa'
~~~
