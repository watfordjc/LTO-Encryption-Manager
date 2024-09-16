namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
	/// <summary>
	/// A SLIP-0021 schema.
	/// </summary>
	/// <param name="firstLevelLabel">The label for the first-level node (child of root node) that defines the meaning of all descendant nodes.</param>
	public class Slip21Schema(string firstLevelLabel)
	{
		/// <summary>
		/// The label for the first-level node (child of root node) that defines the meaning of all descendant nodes.
		/// </summary>
		public string FirstLevelLabel { get; private set; } = firstLevelLabel;
	}
}
