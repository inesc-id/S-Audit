package depskys.core;

// import google.GoogleStorageDriver;
import org.jets3t.service.ServiceException;

import rackspace.RackSpaceDriver;
import amazon.AmazonS3Driver;
import amazon.AuditableAmazonS3Driver;
import amazon.AuditableHashedAmazonS3Driver;
import azure.WindowsAzureDriver;
import depskyDep.IDepSkySDriver;
import depskys.clouds.drivers.AuditableHashLocalDiskDriver;
import depskys.clouds.drivers.AuditableLocalDiskDriver;
import depskys.clouds.drivers.LocalDiskDriver;
import exceptions.StorageCloudException;
import google.GoogleStorageDriver;

/**
 * Factory of IDepSkySDriver objects
 * 
 * @author tiago oliveira
 */
public class DriversFactory {

    static int localPort = 5555;

    /**
     * (all this information come from the account.properties file)
     * 
     * @param type - cloud type
     * @param driverId - cloud id
     * @param accessKey - cloud access key (unique for each user)
     * @param secretKey - cloud secret key (unique for each user)
     * @param clientId
     * @return an object IDepSkyDriver that contains the cloud access for one cloud type
     * @throws StorageCloudException
     * @throws ServiceException
     */

    public static IDepSkySDriver getDriver(String type,
                                           String driverId,
                                           String accessKey,
                                           String secretKey)
            throws StorageCloudException {
        IDepSkySDriver res = null;

        if (type.equals("AMAZON-S3")) {
            res = new AmazonS3Driver(driverId, accessKey, secretKey);
        } else if (type.equals("GOOGLE-STORAGE")) {
            res = new GoogleStorageDriver(driverId, accessKey, secretKey);
        } else if (type.equals("WINDOWS-AZURE")) {
            res = new WindowsAzureDriver(driverId, accessKey, secretKey);
        } else if (type.equals("RACKSPACE")) {
            res = new RackSpaceDriver(driverId, accessKey, secretKey);
        } else if (type.equals("LOCAL")) {
            res = new LocalDiskDriver(driverId, accessKey, new Integer(secretKey).intValue());
            System.out.println("connecting to local cloud->\t" + accessKey + ":" + secretKey);
        }

        return res;
    }

    /**
     * (all this information come from the account.properties file)
     * 
     * @param type - cloud type
     * @param driverId - cloud id
     * @param accessKey - cloud access key (unique for each user)
     * @param secretKey - cloud secret key (unique for each user)
     * @param clientId
     * @return an object IDepSkyDriver that contains the cloud access for one cloud type
     * @throws StorageCloudException
     * @throws ServiceException
     */
    public static IDepSkySDriver getDriver(String type,
                                           String driverId,
                                           String accessKey,
                                           String secretKey,
                                           String pairing_params,
                                           byte[] g,
                                           byte[] w,
                                           byte[] sk)
            throws StorageCloudException {
        IDepSkySDriver res = null;

        if (type.equals("AMAZON-S3")) {
            res = new AmazonS3Driver(driverId, accessKey, secretKey);
        } else if (type.equals("GOOGLE-STORAGE")) {
            res = new GoogleStorageDriver(driverId, accessKey, secretKey);
        } else if (type.equals("WINDOWS-AZURE")) {
            res = new WindowsAzureDriver(driverId, accessKey, secretKey);
        } else if (type.equals("RACKSPACE")) {
            res = new RackSpaceDriver(driverId, accessKey, secretKey);
        } else if (type.equals("AUDITABLE-LOCAL")) {
            System.out.println("initializing audit local:" + driverId);
            res = new AuditableLocalDiskDriver(driverId, accessKey,
                    new Integer(secretKey).intValue(), pairing_params, g, w, sk, false);
            System.out.println(driverId + ":" + res);
            System.out.println("connecting to local cloud->\t" + accessKey + ":" + secretKey);
        } else if (type.equals("AUDITABLE-AMAZON-S3")) {
            System.out.println("initializing audit s3:" + driverId);
            res = new AuditableAmazonS3Driver(driverId, accessKey, secretKey, pairing_params, g, w,
                    sk);
            System.out.println(driverId + ":" + res);
        }

        return res;
    }

    public static IDepSkySDriver getDriver(String type,
                                           String driverId,
                                           String accessKey,
                                           String secretKey,
                                           String pairing_params,
                                           byte[] g,
                                           byte[] w,
                                           byte[] sk,
                                           boolean isOptimized) {
        IDepSkySDriver res = null;

        if (type.equals("AMAZON-S3")) {
            res = new AmazonS3Driver(driverId, accessKey, secretKey);
        } else if (type.equals("GOOGLE-STORAGE")) {
            res = new GoogleStorageDriver(driverId, accessKey, secretKey);
        } else if (type.equals("WINDOWS-AZURE")) {
            res = new WindowsAzureDriver(driverId, accessKey, secretKey);
        } else if (type.equals("RACKSPACE")) {
            res = new RackSpaceDriver(driverId, accessKey, secretKey);
        } else if (type.equals("AUDITABLE-LOCAL")) {
            System.out.println("initializing audit local:" + driverId);
            res = new AuditableLocalDiskDriver(driverId, accessKey,
                    new Integer(secretKey).intValue(), pairing_params, g, w, sk, isOptimized);
            System.out.println(driverId + ":" + res);
            System.out.println("connecting to local cloud->\t" + accessKey + ":" + secretKey);
        } else if (type.equals("AUDITABLE-AMAZON-S3")) {
            System.out.println("initializing audit s3:" + driverId);
            res = new AuditableAmazonS3Driver(driverId, accessKey, secretKey, pairing_params, g, w,
                    sk);
            System.out.println(driverId + ":" + res);
        } else if (type.equals("AUDITABLE-HASH-LOCAL")) {
            System.out.println("initializing audit local:" + driverId);
            res = new AuditableHashLocalDiskDriver(driverId, accessKey, pairing_params, g, w, sk,
                    100.0);
            System.out.println(driverId + ":" + res);
            System.out.println("connecting to local cloud->\t" + accessKey + ":" + secretKey);
        } else if (type.equals("AUDITABLE-HASH-AMAZON-S3")) {
            System.out.println("initializing audit s3:" + driverId);
            res = new AuditableHashedAmazonS3Driver(driverId, accessKey, secretKey, pairing_params,
                    g, w, sk, 100.0);
            System.out.println(driverId + ":" + res);
        }

        return res;

    }
}
