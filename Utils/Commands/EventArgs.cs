using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Commands
{
    public class EventArgs<T>(T value) : EventArgs
    {
		public T Value { get; private set; } = value;
	}
}
