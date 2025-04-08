import { DepGraph } from "@snyk/dep-graph";
import * as path from "path";
import * as lockFileParser from "snyk-poetry-lockfile-parser";
import { DepGraphFact, TestedFilesFact } from "../../../facts";
import { AppDepsScanResultWithoutTarget, FilePathToContent } from "../types";

interface ManifestLockPathPair {
  manifest: string;
  lock: string;
}

export async function poetryFilesToScannedProjects(
  filePathToContent: FilePathToContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  console.log("CUSTOM DOCKER PLUGIN: Poetry files scan started");
  // Try to detect if we're using the custom version
  console.log("CUSTOM DOCKER PLUGIN: Using custom Poetry lockfile parser");
  
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  const filePairs = findManifestLockPairsInSameDirectory(filePathToContent);
  console.log("CUSTOM DOCKER PLUGIN: Found Poetry file pairs:", JSON.stringify(filePairs));

  const shouldIncludeDevDependencies = false;

  for (const pathPair of filePairs) {
    console.log("CUSTOM DOCKER PLUGIN: Processing Poetry files:", pathPair.manifest, pathPair.lock);
    console.log("CUSTOM DOCKER PLUGIN: Manifest content sample:", filePathToContent[pathPair.manifest].substring(0, 200) + "...");
    console.log("CUSTOM DOCKER PLUGIN: Lock file content sample:", filePathToContent[pathPair.lock].substring(0, 200) + "...");
    
    const depGraph = await lockFileParser.buildDepGraph(
      filePathToContent[pathPair.manifest],
      filePathToContent[pathPair.lock],
      shouldIncludeDevDependencies,
    );
    
    if (!depGraph) {
      console.log("CUSTOM DOCKER PLUGIN: Failed to build Poetry dependency graph");
      continue;
    }
    
    console.log("CUSTOM DOCKER PLUGIN: Successfully built Poetry dependency graph");

    const depGraphFact: DepGraphFact = {
      type: "depGraph",
      data: depGraph as DepGraph,
    };
    const testedFilesFact: TestedFilesFact = {
      type: "testedFiles",
      data: [path.basename(pathPair.manifest), path.basename(pathPair.lock)],
    };
    scanResults.push({
      facts: [depGraphFact, testedFilesFact],
      identity: {
        type: depGraph.pkgManager.name,
        targetFile: pathPair.manifest,
      },
    });
  }

  return scanResults;
}

function findManifestLockPairsInSameDirectory(
  filePathToContent: FilePathToContent,
): ManifestLockPathPair[] {
  const fileNamesGroupedByDirectory = groupFilesByDirectory(filePathToContent);
  const manifestLockPathPairs: ManifestLockPathPair[] = [];

  for (const directoryPath of Object.keys(fileNamesGroupedByDirectory)) {
    const filesInDirectory = fileNamesGroupedByDirectory[directoryPath];
    if (filesInDirectory.length !== 2) {
      // either a missing file or too many files, ignore
      continue;
    }

    const hasManifest = filesInDirectory.includes("pyproject.toml");
    const hasLockFile = filesInDirectory.includes("poetry.lock");

    if (hasManifest && hasLockFile) {
      manifestLockPathPairs.push({
        manifest: path.join(directoryPath, "pyproject.toml"),
        lock: path.join(directoryPath, "poetry.lock"),
      });
    }
  }

  return manifestLockPathPairs;
}

// assumption: we only care about manifest+lock files if they are in the same directory
function groupFilesByDirectory(filePathToContent: FilePathToContent): {
  [directoryName: string]: string[];
} {
  const fileNamesGroupedByDirectory: { [directoryName: string]: string[] } = {};
  for (const filePath of Object.keys(filePathToContent)) {
    const directory = path.dirname(filePath);
    const fileName = path.basename(filePath);
    if (!fileNamesGroupedByDirectory[directory]) {
      fileNamesGroupedByDirectory[directory] = [];
    }
    fileNamesGroupedByDirectory[directory].push(fileName);
  }
  return fileNamesGroupedByDirectory;
}
