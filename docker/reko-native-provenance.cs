using Reko.Core;
using Reko.Core.Absyn;
using Reko.Core.Code;
using Reko.Core.Expressions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Reko;

internal sealed class NativeVariableProvenance
{
    private const string Schema = "decbench-reko-native-provenance-v1";

    private readonly string outputPath;
    private readonly Dictionary<Procedure, Dictionary<Identifier, SortedSet<ulong>>> addresses;

    private NativeVariableProvenance(
        string outputPath,
        Dictionary<Procedure, Dictionary<Identifier, SortedSet<ulong>>> addresses)
    {
        this.outputPath = outputPath;
        this.addresses = addresses;
    }

    internal static NativeVariableProvenance? CaptureIfRequested(IEnumerable<Program> programs)
    {
        var outputPath = Environment.GetEnvironmentVariable("DECBENCH_REKO_PROVENANCE");
        if (string.IsNullOrWhiteSpace(outputPath))
            return null;

        try
        {
            return Capture(outputPath, programs);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static NativeVariableProvenance Capture(
        string outputPath,
        IEnumerable<Program> programs)
    {
        var byProcedure = new Dictionary<Procedure, Dictionary<Identifier, SortedSet<ulong>>>(
            ReferenceEqualityComparer.Instance);
        foreach (var procedure in programs
            .SelectMany(program => program.Procedures.Values)
            .OrderBy(procedure => procedure.EntryAddress))
        {
            var byIdentifier = new Dictionary<Identifier, SortedSet<ulong>>(
                ReferenceEqualityComparer.Instance);
            foreach (var statement in procedure.Statements)
            {
                if (!HasNativeOrigin(statement.Instruction))
                    continue;
                var collector = new AddressCollector(statement.Address.ToLinear(), byIdentifier);
                statement.Instruction.Accept(collector);
            }
            byProcedure.Add(procedure, byIdentifier);
        }
        return new NativeVariableProvenance(outputPath, byProcedure);
    }

    internal void Write(IEnumerable<Program> programs)
    {
        try
        {
            WriteCore(programs);
        }
        catch (Exception)
        {
        }
    }

    private void WriteCore(IEnumerable<Program> programs)
    {
        var functions = new List<object>();
        foreach (var procedure in programs
            .SelectMany(program => program.Procedures.Values)
            .OrderBy(procedure => procedure.EntryAddress))
        {
            if (procedure.Body is null || !addresses.TryGetValue(procedure, out var byIdentifier))
                continue;
            var finalIdentifiers = new FinalIdentifierCollector();
            finalIdentifiers.Collect(procedure.Body);
            var variables = finalIdentifiers.Identifiers
                .Where(identifier => IsCIdentifier(identifier.Name))
                .GroupBy(identifier => identifier.Name, StringComparer.Ordinal)
                .Where(group => group.Count() == 1)
                .Select(group => group.Single())
                .Where(byIdentifier.ContainsKey)
                .Select(identifier => new
                {
                    name = identifier.Name,
                    addresses = byIdentifier[identifier].ToArray(),
                })
                .Where(variable => variable.addresses.Length > 0)
                .OrderBy(variable => variable.name, StringComparer.Ordinal)
                .ToArray();
            functions.Add(new
            {
                name = procedure.Name,
                address = procedure.EntryAddress.ToLinear(),
                variables,
            });
        }

        var directory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
        var temporary = $"{outputPath}.{Guid.NewGuid():N}.tmp";
        var payload = JsonSerializer.Serialize(
            new { schema = Schema, functions },
            new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(temporary, payload);
        File.Move(temporary, outputPath, true);
    }

    private static bool HasNativeOrigin(Instruction instruction)
    {
        return instruction is not AliasAssignment
            and not CodeComment
            and not DefInstruction
            and not PhiAssignment
            and not UseInstruction;
    }

    private static bool IsCIdentifier(string name)
    {
        if (string.IsNullOrEmpty(name) || !(name[0] == '_' || char.IsLetter(name[0])))
            return false;
        return name.Skip(1).All(character => character == '_' || char.IsLetterOrDigit(character));
    }

    private sealed class AddressCollector : InstructionVisitorBase
    {
        private readonly ulong address;
        private readonly Dictionary<Identifier, SortedSet<ulong>> addresses;

        internal AddressCollector(
            ulong address,
            Dictionary<Identifier, SortedSet<ulong>> addresses)
        {
            this.address = address;
            this.addresses = addresses;
        }

        public override void VisitCallInstruction(CallInstruction call)
        {
            base.VisitCallInstruction(call);
            foreach (var binding in call.Uses)
                binding.Expression.Accept(this);
            foreach (var binding in call.Definitions)
                binding.Expression.Accept(this);
        }

        public override void VisitIdentifier(Identifier identifier)
        {
            if (!addresses.TryGetValue(identifier, out var identifierAddresses))
            {
                identifierAddresses = [];
                addresses.Add(identifier, identifierAddresses);
            }
            identifierAddresses.Add(address);
        }
    }

    private sealed class FinalIdentifierCollector : InstructionVisitorBase, IAbsynVisitor
    {
        internal HashSet<Identifier> Identifiers { get; } = new(ReferenceEqualityComparer.Instance);

        internal void Collect(IEnumerable<AbsynStatement> statements)
        {
            foreach (var statement in statements)
                statement.Accept(this);
        }

        public override void VisitIdentifier(Identifier identifier)
        {
            Identifiers.Add(identifier);
        }

        public void VisitAssignment(AbsynAssignment assignment)
        {
            assignment.Dst.Accept(this);
            assignment.Src.Accept(this);
        }

        public void VisitBreak(AbsynBreak breakStatement)
        {
        }

        public void VisitCase(AbsynCase caseStatement)
        {
        }

        public void VisitCompoundAssignment(AbsynCompoundAssignment assignment)
        {
            VisitAssignment(assignment);
        }

        public void VisitContinue(AbsynContinue continueStatement)
        {
        }

        public void VisitDeclaration(AbsynDeclaration declaration)
        {
            declaration.Identifier.Accept(this);
            declaration.Expression?.Accept(this);
        }

        public void VisitDefault(AbsynDefault defaultStatement)
        {
        }

        public void VisitDoWhile(AbsynDoWhile loop)
        {
            Collect(loop.Body);
            loop.Condition.Accept(this);
        }

        public void VisitFor(AbsynFor loop)
        {
            loop.Initialization?.Accept(this);
            loop.Condition.Accept(this);
            loop.Iteration?.Accept(this);
            Collect(loop.Body);
        }

        public void VisitGoto(AbsynGoto gotoStatement)
        {
        }

        public void VisitIf(AbsynIf ifStatement)
        {
            ifStatement.Condition.Accept(this);
            Collect(ifStatement.Then);
            Collect(ifStatement.Else);
        }

        public void VisitLabel(AbsynLabel label)
        {
        }

        public void VisitLineComment(AbsynLineComment comment)
        {
        }

        public void VisitReturn(AbsynReturn returnStatement)
        {
            returnStatement.Value?.Accept(this);
        }

        public void VisitSideEffect(AbsynSideEffect sideEffect)
        {
            sideEffect.Expression.Accept(this);
        }

        public void VisitSwitch(AbsynSwitch switchStatement)
        {
            switchStatement.Expression.Accept(this);
            Collect(switchStatement.Statements);
        }

        public void VisitWhile(AbsynWhile loop)
        {
            loop.Condition.Accept(this);
            Collect(loop.Body);
        }
    }
}
