using KeyDerivation.Keys;
using System.Threading;
using System.Threading.Tasks;

namespace TuviPgpLib
{
    /// <summary>
    /// Password protected key storage
    /// </summary>
    public interface IKeyStorage
    {
        /// <summary>
        /// Initialize <paramref name="masterKey"/>.
        /// </summary>
        /// <exception cref="DataBaseException" />
        Task InitializeMasterKeyAsync(MasterKey masterKey, CancellationToken cancellationToken = default);

        /// <summary>
        /// Check if master key is stored.
        /// </summary>
        Task<bool> IsMasterKeyExistAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Extracts stored master key.
        /// </summary>
        Task<MasterKey> GetMasterKeyAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Stores PGP public key ring bundle.
        /// </summary>
        void SavePgpPublicKeys(PgpPublicKeyBundle keyBundle);

        /// <summary>
        /// Stores PGP secret key ring bundle.
        /// </summary>
        void SavePgpSecretKeys(PgpSecretKeyBundle keyBundle);

        /// <summary>
        /// Extracts PGP public key ring bundle.
        /// </summary>
        Task<PgpPublicKeyBundle> GetPgpPublicKeysAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Extracts PGP secret key ring bundle.
        /// </summary>
        Task<PgpSecretKeyBundle> GetPgpSecretKeysAsync(CancellationToken cancellationToken = default);
    }
}
