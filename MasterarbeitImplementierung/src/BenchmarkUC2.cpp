#define PROFILE

#include "openfhe.h"
#include <json/json.h>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;


struct Party {
public:
    usint id;  // unique party identifier starting from 0

    std::vector<Ciphertext<DCRTPoly>> sharesPair;  // (h_{0,i}, h_{1,i}) = (masked decryption
                                                   // share, re-encryption share)
                                                   // we use a vector inseat of std::pair for Python API compatibility

    KeyPair<DCRTPoly> kpShard;  // key-pair shard 
};

struct FleetData {
    std::vector<double> driverIDs;
    std::vector<double> locLat;
    std::vector<double> locLong;
    std::vector<double> distanceTravelled;
    std::vector<double> co2Emissions;
    std::vector<double> emissionFactor;
    std::vector<double> speed;
    std::vector<double> fuelConsumption;
    std::vector<double> cargoWeight;
};

struct FleetDataCipher {
    Ciphertext<DCRTPoly> driverIDs;
    Ciphertext<DCRTPoly> locLat;
    Ciphertext<DCRTPoly> locLong;
    Ciphertext<DCRTPoly> distanceTravelled;
    Ciphertext<DCRTPoly> co2Emissions;
    Ciphertext<DCRTPoly> emissionFactor;
    Ciphertext<DCRTPoly> speed;
    Ciphertext<DCRTPoly> fuelConsumption;
    Ciphertext<DCRTPoly> cargoWeight;
};

struct FleetDataPlaintext {
    Plaintext driverIDs;
    Plaintext locLat;
    Plaintext locLong;
    Plaintext distanceTravelled;
    Plaintext co2Emissions;
    Plaintext emissionFactor;
    Plaintext speed;
    Plaintext fuelConsumption;
    Plaintext cargoWeight;
};

std::map<int, FleetData> fleetMap;

    ////////////////////////////////////////////////////////////////
    // Ergebisse  
    ////////////////////////////////////////////////////////////////

struct Results {
    std::string TimeStamp       = "";  
    std::string Comment         = "";
    int Batchsize               = -1;  
    ScalingTechnique ScalingTech   = ScalingTechnique::INVALID_RS_TECHNIQUE;
    SecurityLevel SecLevel      = SecurityLevel::HEStd_NotSet;
    COMPRESSION_LEVEL CompressionLevel  = COMPRESSION_LEVEL::COMPACT;
    int ScaleModSize            = -1;
    int FirstModSize            = -1;
    int RingDimension           = -1;
    int MultiplicativeDepth     = -1;
    int Parties                 = -1;
    double Log2q                = -1.0;     //Log2(q) von Ciphertext Modulus zur Bewertung der Sicherheitsstufe
    // all durations are measured in ms
    int DurOverall         = -1;   //Overall duration of benchmarking one parameter set
    double DurEncryption        = -1.0;     //Duration to encrypt and bootstrap all vectors of RawInput
    double DurDecryption        = 0.0;     //Duration to decrypt the 4 result vectors
    double DurEncoding          = -1.0;     // Duration to encode plaintext
    double DurKeyGen            = -1.0;     // Duration of key generation process 
    double CO2e_Dur             = -1.0;     // Duration of whole CO2e calculation incl. bootstrapping
    int CO2e_BS_Dur             = -1;       //Duration of bootstrapping with one iteration
    int CO2e_BS_LvlAfter        = -1;       //Level after Bootstrapping
    double CO2e_BS_Throughput   = -1.0;
    double CO2e_Calc_DurCalcMult    = 0;    //Duration of multiplication in CO2e calculation
    double PCor_Calc_DurCalcMean    = 0;    //Duration of mean calculation in CO2e calculation
    double CO2e_BS_PrecAfter    = -1.0;     //precision of CO2e result in bit after Bootstrapping
    double CO2e_Calc_PrecAfter  = -1.0;     //precision of CO2e result in bit before Bootstrapping
    double CO2e_Calc_Dur        = -1.0;     //Duration of calculating CO2e on the first cipher text
    int CO2e_Calc_LvlBefore     = -1;
    int CO2e_Calc_LvlAfter      = -1;
    double Var_Dur              = -1.0;     // Duration for whole variance calculation incl. bootstrapping
    int Var_BS_Dur              = -1;       //Duration of bootstrapping with one iteration
    int Var_BS_LvlAfter         = -1;
    double Var_BS_Throughput    = -1.0;
    double Var_Calc_DurCalcMean = 0.0; //Duration of add many in variance calculation
    double Var_Calc_DurCalcSub  = 0.0; //Duration of substraction in variance calculation
    double Var_Calc_DurCalcSq   = 0.0; //Duration of square in variance calculation    
    double Var_Calc_Dur         = -1.0; //Duration of calculating variance of all cipher text
    double Var_BS_PrecAfter     = -1.0;   //precision of CO2e result in bit after Bootstrapping
    double Var_Calc_PrecAfter   = -1.0;   //precision of CO2e result in bit before Bootstrapping
    int Var_Calc_LvlBefore      = -1;
    int Var_Calc_LvlAfter       = -1;
    double SDev_Dur             = -1.0; // Duration for whole standard deviation calculation incl. bootstrapping
    int SDev_BS_Dur              = -1;   //Duration of bootstrapping with one iteration
    int SDev_BS_LvlAfter         = -1;
    double SDev_BS_Throughput    = -1.0;
    double SDev_Calc_DurCalcMean  = 0; //Duration of add many in standard deviation calculation
    double SDev_Calc_DurCalcSub  = 0.0; //Duration of substraction in standard deviation calculation
    double SDev_Calc_DurCalcSq   = 0.0; //Duration of square in standard deviation calculation    
    double SDev_Calc_DurCalcRSq  = 0.0; //Duration of square in standard deviation calculation    
    double SDev_Calc_Dur         = -1.0; //Duration of calculating variance of all cipher text
    double SDev_BS_PrecAfter     = -1.0;   //precision of standard deviation result in bit after Bootstrapping
    double SDev_Calc_PrecAfter   = -1.0;   //precision of standard deviation result in bit before Bootstrapping
    int SDev_Calc_LvlBefore      = -1;
    double PCor_Dur              = -1.0; // Duration for whole pearson correlation calculation incl. bootstrapping
    double PCor_BS_Dur           = 0.0;   //Duration of bootstrapping
    int PCor_BS_LvlAfter         = -1;
    double PCor_BS_Throughput    = -1.0;
    double PCor_Calc_DurCalcSq  = 0.0; //Duration of add many in PCoriance calculation
    double PCor_Calc_DurCalcDiv  = 0.0; //Duration of division in PCoriance calculation
    double PCor_Calc_DurCalcRSq  = 0.0; //Duration of square in PCoriance calculation    
    double PCor_Calc_Dur         = -1.0; //Duration of calculating PCoriance of all cipher text
    double PCor_BS_PrecAfter     = -1.0;   //precision of CO2e result in bit after Bootstrapping
    int PCor_Calc_LvlBefore      = -1;
    // all sizes are measured in kb
    int SizeCryptoContext       = -1;   //size of crypto context
    int SizeEvalMultKey         = -1;   //size of MultKey
    int SizeEvalSumKey          = -1;   //size of SumKey
    int SizeData                = -1;   //size of ciphertext
    // throughput is measured in kb/s
    double ThroughputEncryption = -1.0;
    double ThroughputDecryption = -1.0;
    std::string CO2e_ResExp     = "";   //string output of expected CO2e result
    std::string CO2e_ResAct     = "";   //string output of actual CO2e result
    std::string PCor_ResExp     = "";   //string output of expected mean result
    std::string PCor_ResAct     = "";   //string output of actual mean result
    std::string Var_ResExp      = "";   //string output of expected variance result
    std::string Var_ResAct      = "";   //string output of actual variance result
    std::string SDev_ResExp     = "";   //string output of expected standard deviation result
    std::string SDev_ResAct     = "";   //string output of actual standard deviation result
};

class FHEBenchmark {
    private:
        CryptoContext<DCRTPoly> cryptoContext;
        KeyPair<DCRTPoly> kpMultiparty;  
        std::vector<Party> parties;      
        std::map<int, FleetDataCipher> CipherInput;
        std::map<int, FleetDataPlaintext> PlaintextInput;
        std::vector<Ciphertext<DCRTPoly>> CO2eResult;
        std::vector<Ciphertext<DCRTPoly>> PCorResult;
        std::vector<Ciphertext<DCRTPoly>> VarResult;
        std::vector<Ciphertext<DCRTPoly>> SDevResult;
        uint32_t numSlots;
        uint32_t numParties;
        usint depth;
        std::vector<uint32_t> levelBudget;
        std::vector<uint32_t> bsgsDim;


    ///////////////////////////////////////////////////////////////
    // Initialzie Plaintext vectors  
    ////////////////////////////////////////////////////////////////
        std::vector<double> RawCO2e, RawPCor, RawVar, RawSDev;
        Results bm_results;

        /**
         * Calculates the CO2e (carbon dioxide equivalent) for each element in the input vector.
         * CO2e is calculated as sum of (CargoWeight * distanceTravelled * EmissionFactor).
         *
         * @param input The input vector of doubles.
         * @return The vector containing the CO2e values.
         */
        std::vector<double> CalcPlaintextCO2e() {

            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {
                double co2e = 0.0;

                for(size_t i = 0; i < data.cargoWeight.size(); i++){
                    co2e += data.cargoWeight[i] * data.distanceTravelled[i] * data.emissionFactor[i];
                }
                result.push_back(co2e);
            }

            return result;
        }

        /**
         * Calculates the mean value for each element in the input vector of vectors.
         *
         * @param input The input vector of vectors of doubles.
         * @return The vector containing the mean values.
         */
        std::vector<double> CalcPlaintextPearsonCorr() {
            int n = fleetMap[0].cargoWeight.size();    // number of data points

            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {

                // calculate mean values of fuel consumption and cargo weight
                // fuel consumption = input[6]
                // cargo weight = input[7]
                double meanFuelConsumption = 0.0, meanCargoWeight = 0.0;
                for (int i = 0; i < n; ++i) {
                    meanFuelConsumption += data.fuelConsumption[i];
                    meanCargoWeight += data.cargoWeight[i];
                }

                meanFuelConsumption /= n;
                meanCargoWeight /= n;

                // calculate sum of products of the deviations
                double sum_product_deviations = 0.0, sum_squared_fuelcons = 0.0, sum_squared_cargow = 0.0;
                for (int i = 0; i < n; ++i) {
                    double devFuelCons = data.fuelConsumption[i] - meanFuelConsumption;
                    double devCargoW = data.cargoWeight[i] - meanCargoWeight;
                    sum_product_deviations += devFuelCons * devCargoW;
                    sum_squared_fuelcons += devFuelCons * devFuelCons;
                    sum_squared_cargow += devCargoW * devCargoW;
                }

                // calculate correlation coefficients
                double correlation_coefficient = sum_product_deviations / (sqrt(sum_squared_fuelcons) * sqrt(sum_squared_cargow));
                result.push_back(correlation_coefficient);
            }

            // return as vec
            return result;
        }


    ////////////////////////////////////////////////////////////////
    // Variance 
    ////////////////////////////////////////////////////////////////
        
        /**
         * Calculates the variance of fuel consumption.
         *
         * @param input The input vector of vectors of doubles.
         * @return The vector containing the variance values.
         */
        std::vector<double> CalcPlaintextVar() {
            int n = fleetMap[0].cargoWeight.size();    // number of data points
            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {

                double mean = 0.0;
                for(int i = 0; i < n; i++){
                    mean += data.fuelConsumption[i];
                }
                mean /= n;

                // Sum (x_i - µ)^2 calculation
                double sum = 0.0;
                for(int i = 0; i < n; i++){
                     sum += std::pow((data.fuelConsumption[i]- mean),2);
                }

                sum /= n;

                result.push_back(sum);
            }

            return result;
        }

        /**
         * Calculates the standard deviation for each element in the input vector of vectors.
         *
         * @param input The input vector of vectors of doubles.
         * @return The vector containing the variance values.
         */

    ////////////////////////////////////////////////////////////////
    // StandDeviation  
    ////////////////////////////////////////////////////////////////
        std::vector<double> CalcPlaintextSDev() {
            double max = std::numeric_limits<double>::min();
            double min = std::numeric_limits<double>::max();

            int n = fleetMap[0].cargoWeight.size();    // number of data points
            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {

                double mean = 0.0;
                for(int i = 0; i < n; i++){
                    mean += data.fuelConsumption[i];
                }
                mean /= n;

                // Sum (x_i - µ)^2 calculation
                double sum = 0.0;
                for(int i = 0; i < n; i++){
                     sum += std::pow((data.fuelConsumption[i]- mean),2);
                }

                sum /= n;

                max = (sum > max) ? sum : max;
                min = (sum < min) ? sum : min;

                result.push_back(std::sqrt(sum));
            }
          //  std::cout << "SDev_min: " << min << "\nSDev_max: " << max << std::endl;

            return result;
        }


        
    ////////////////////////////////////////////////////////////////
    // Approximation Error Between PlainText and AfterBS  
    ////////////////////////////////////////////////////////////////
        /**
         * Calculates the approximation error between two vectors of complex numbers.
         *
         * @param result The vector containing the calculated complex numbers.
         * @param expectedResult The vector containing the expected complex numbers.
         * @return The approximation error.
         * @throws config_error if the vectors have different sizes.
         */
        double CalculateApproximationError(const std::vector<double>& result,
                                            const std::vector<double>& expectedResult) {
            if (result.size() != expectedResult.size())
                OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

            // Using the infinity norm
            double maxError = 0;
            for (size_t i = 0; i < result.size(); ++i) {
                double error = std::abs(result[i] - expectedResult[i]);
                if (maxError < error)
                    maxError = error;
            }

            return std::log2(maxError);
        }

        /**
         * Calculates the approximation error between two vectors of complex numbers.
         *
         * @param result The vector containing the calculated complex numbers.
         * @param expectedResult The vector containing the expected complex numbers.
         * @return The approximation error.
         * @throws config_error if the vectors have different sizes.
         */

        
    ////////////////////////////////////////////////////////////////
    // Approximation Error Between PlainText and AfterBS   (View jus on Real-part) 
    ////////////////////////////////////////////////////////////////

        double CalculateApproximationError(const std::vector<double>& result,
                                            const std::vector<std::complex<double>>& expectedResult) {
            
            // Using the infinity norm
            double maxError = 0;
            for (size_t i = 0; i < result.size(); ++i) {
                double error = std::abs(result[i] - expectedResult[i].real());
                if (maxError < error)
                    maxError = error;
            }

            double prec = std::log2(maxError);

            if(std::isfinite(prec)) {
                return prec;
            }
            else{
                return -1.0;
            }
             
        }

        /**
         * Calculates the approximation error between two vectors of complex numbers.
         *
         * @param result The vector containing the calculated complex numbers.
         * @param expectedResult The vector containing the expected complex numbers.
         * @param length How many entries shall be evaluated
         * @return The approximation error.
         * @throws config_error if the vectors have different sizes.
         */
        double CalculateApproximationError(const std::vector<double>& result,
                                            const std::vector<std::complex<double>>& expectedResult, int length) {
            
            // Using the infinity norm
            double maxError = 0;
            for (int i = 0; i < length; ++i) {
                double error = std::abs(result[i] - expectedResult[i].real());
                if (maxError < error)
                    maxError = error;
            }

            double prec = std::log2(maxError);

            if(std::isfinite(prec)) {
                return prec;
            }
            else{
                return -1.0;
            }
             
        }

        /**
         * Gets the current timestamp in the format "YYYY-MM-DD HH:MM:SS".
         *
         * @return The current timestamp as a string.
         */
        std::string getCurrentTimestamp() {
            // Get current time
            auto now = std::chrono::system_clock::now();
            std::time_t currentTime = std::chrono::system_clock::to_time_t(now);

            // Convert to tm struct
            std::tm tmTime = *std::localtime(&currentTime);

            // Using std::put_time to format date/time
            std::stringstream ss;
            ss << std::put_time(&tmTime, "%Y-%m-%d %H:%M:%S"); // Format: YYYY-MM-DD HH:MM:SS
            return ss.str();
        }

        /**
         * Prints the elements of a vector up to a specified number of elements.
         *
         * @param FirstText The text to print before the vector elements.
         * @param vec The vector to print.
         * @param numElements The number of elements to print (-1 to print all).
         */
        void printVector(std::string FirstText, const std::vector<double>& vec, int numElements = -1) {
            std::cout << FirstText;
            int count = 0;
            for (const double& element : vec) {
                if (numElements == -1 || count < numElements) {
                    std::cout << std::fixed << std::setprecision(4) << element << " ";
                    count++;
                } else {
                    break;
                }
            }
            std::cout << std::endl;
        }

        /**
         * Converts a string of double values into a vector of doubles
         * @param str string that contains double values separated by space, comma or tabulator.
        */
        std::vector<double> stringToDoubleVector(const std::string& str) {
            std::vector<double> result;
            std::stringstream ss(str);

            double value;
            while (ss >> value) {
                result.push_back(value);

                while (ss.peek() == ' ' || ss.peek() == ',' || ss.peek() == '\t') {
                    ss.ignore();
                }
            }

            return result;
        }

        std::string vectorToFormattedString(const std::vector<double>& vec, int length) {
            std::ostringstream oss;

            for ( int i = 0; i < length; ++i) {
                oss << std::fixed << std::setprecision(10) << vec[i] << " ";
            }

            return oss.str();
        }

    public:
        FHEBenchmark(ScalingTechnique rescaleTech, SecurityLevel seclvl, int numparties, int scalemodsize, int firstmodsize, COMPRESSION_LEVEL complvl, int depth){
          
    ////////////////////////////////////////////////////////////
    // Initialze Crypto Context
    ////////////////////////////////////////////////////////////

            CCParams<CryptoContextCKKSRNS> parameters;
            SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
            parameters.SetSecretKeyDist(secretKeyDist);
            parameters.SetSecurityLevel(seclvl);     // Ring diemsion will be calcualted by bib, based log(q) (Depends on Mult Depth Scaling Factor) Automatism by Bib 
            if(seclvl == SecurityLevel::HEStd_NotSet){  //show table 
                parameters.SetRingDim(1024);
            }

            numSlots = 32;

            parameters.SetBatchSize(numSlots);
            parameters.SetScalingModSize(scalemodsize);
            parameters.SetFirstModSize(firstmodsize);
            parameters.SetKeySwitchTechnique(KeySwitchTechnique::HYBRID);

            parameters.SetScalingTechnique(rescaleTech);

            parameters.SetMultiplicativeDepth(depth); 
            

    ////////////////////////////////////////////////////////////
    // Set Protocol  
    ////////////////////////////////////////////////////////////

            /*  Protocol-specific parameters (SLACK or COMPACT)
            * SLACK (default) uses larger masks, which makes it more secure theoretically. However, it is also slightly less efficient.
            * COMPACT uses smaller masks, which makes it more efficient. However, it is relatively less secure theoretically.
            * Both options can be used for practical security.
            * The following table summarizes the differences between SLACK and COMPACT:
            * 
            * 
            * Parameter	        SLACK	                                        COMPACT
            * Mask size	        Larger	                                        Smaller
            * Security	        More secure	                                    Less secure
            * Efficiency	    Less efficient	                                More efficient
            * Recommended use	For applications where security is paramount 	For applications where efficiency is paramount    paramount =große Bedeutung
            */
            parameters.SetInteractiveBootCompressionLevel(complvl);

            // Generate crypto context.
            cryptoContext = GenCryptoContext(parameters);

            // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
            cryptoContext->Enable(PKE);
            cryptoContext->Enable(KEYSWITCH);
            cryptoContext->Enable(LEVELEDSHE);
            cryptoContext->Enable(ADVANCEDSHE);
            cryptoContext->Enable(MULTIPARTY); //enable neccessary  

            
////////////////////////////////////////////////////////////
// Perform Key Generation Operation
 ////////////////////////////////////////////////////////////
   
   
   
    ////////////////////////////////////////////////////////////
    // Joint Public Key  MPC
    ////////////////////////////////////////////////////////////
            
           // std::vector<int32_t> indices = {1,2,3};

            // Initialization - Assuming numParties (n) of parties
            // P_n is the leading party

            std::cout << "Key generation for " << numparties << " parties started." << std::endl;
            numParties = numparties;
            for (int i = 0; i < numparties; i++) {
                Party party;
                party.id = i;
                if (0 == i)
                    party.kpShard = cryptoContext->KeyGen();  // Party A == 0  create SecretKey 
                else
                    party.kpShard = cryptoContext->MultipartyKeyGen(parties[i-1].kpShard.publicKey);
                parties.push_back(party);
            }

            std::cout << "Joint public key for (s_0 + s_1 + ... + s_n) is generated..." << std::endl;


            TimeVar t;
            TIC(t); //start timer for DurKeyGen


            ////////////////////////////////////////////////////////////
            // Generate Distributed EvalMultKey 
            ////////////////////////////////////////////////////////////
            std::cout << "EvalMultKey generation started." << std::endl;            

            std::vector<EvalKey<DCRTPoly>> EvalMultKeyTemp;
            EvalKey<DCRTPoly> evalMultKeyFinal;
            for(int i = 0; i<numparties; i++)
            {
                if(i==0){
                    EvalMultKeyTemp.push_back(cryptoContext->KeySwitchGen(parties[i].kpShard.secretKey, parties[i].kpShard.secretKey));
                }
                else{
                    //Generiert einen kombinierten Evaluierungsschlüssel aus dem aktuellen geheimen Anteil und einem zuvor kombinierten Evaluierungsschlüssel.
                    auto EvalMultKeyi = cryptoContext->MultiKeySwitchGen(parties[i].kpShard.secretKey, parties[i].kpShard.secretKey, EvalMultKeyTemp[0]);  

                    EvalMultKeyTemp.push_back(cryptoContext->MultiAddEvalKeys(EvalMultKeyTemp[i-1], EvalMultKeyi, parties[i].kpShard.publicKey->GetKeyTag())); //KeyTag ID 

                    std::vector<EvalKey<DCRTPoly>> EvalMultKeyAdd; 
                    for(int j=0; j< numparties; j++){
                        EvalMultKeyAdd.push_back(cryptoContext->MultiMultEvalKey(parties[j].kpShard.secretKey, EvalMultKeyTemp[i], parties[i].kpShard.publicKey->GetKeyTag()));
                    }

                    evalMultKeyFinal = cryptoContext->MultiAddEvalMultKeys(EvalMultKeyAdd[0], EvalMultKeyAdd[1], EvalMultKeyAdd[0]->GetKeyTag()); //combine allKeys via MultiAddEvalMultKeys()
                    for(int j=2; j<numparties; j++){
                        evalMultKeyFinal = cryptoContext->MultiAddEvalMultKeys(evalMultKeyFinal, EvalMultKeyAdd[j], EvalMultKeyAdd[j]->GetKeyTag()); 
                    }
                }

            }
            cryptoContext->InsertEvalMultKey({evalMultKeyFinal}); //is avaible in CryptoContext 


            ////////////////////////////////////////////////////////////
            // Generate Distributed EvalSumKey 
            ////////////////////////////////////////////////////////////
            std::cout << "EvalSumKey generation started." << std::endl;
            // Generate evalsum key part for first party
            cryptoContext->EvalSumKeyGen(parties[0].kpShard.secretKey);
            auto evalSumKeys =
                std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cryptoContext->GetEvalSumKeyMap(parties[0].kpShard.secretKey->GetKeyTag()));

            std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> evalSumkKeysJoin;

            for (int i = 1; i < numparties; i++) {
                auto evalSumkKeysPartyi = cryptoContext->MultiEvalSumKeyGen(parties[i].kpShard.secretKey, evalSumKeys, parties[i].kpShard.publicKey->GetKeyTag());
                if(i==1){
                    evalSumkKeysJoin = cryptoContext->MultiAddEvalSumKeys(evalSumKeys, evalSumkKeysPartyi, parties[i].kpShard.publicKey->GetKeyTag());
                }
                else{
                    evalSumkKeysJoin = cryptoContext->MultiAddEvalSumKeys(evalSumkKeysJoin, evalSumkKeysPartyi, parties[i].kpShard.publicKey->GetKeyTag());
                }
                cryptoContext->InsertEvalSumKey(evalSumkKeysJoin);  //is avaible in CryptoContext                  
            }

            // Assert everything is good
            for (int i = 0; i < numparties; i++) {
                if (!parties[i].kpShard.good()) {
                    std::cout << "Key generation failed for party " << i << "!" << std::endl;
                    exit(1);
                }
            }            
           
           
             // END of Key Generation

            ////////////////////////////////////////////////////////////
            // // Generate the collective private key (Only for Debugging) , Proves 
            ////////////////////////////////////////////////////////////

            std::vector<PrivateKey<DCRTPoly>> secretKeys;
            for (int i = 0; i < numparties; i++) {
                secretKeys.push_back(parties[i].kpShard.secretKey);
            }
            kpMultiparty = cryptoContext->MultipartyKeyGen(secretKeys);  // This is the same core key generation operation. Just for Debugging Puposses


            bm_results.DurKeyGen = TOC_US(t) / 1000.0;

            //Make calculations on plaintext
            RawCO2e = CalcPlaintextCO2e();
            RawPCor = CalcPlaintextPearsonCorr();
            RawVar  = CalcPlaintextVar();
            RawSDev = CalcPlaintextSDev();

            //Add input variables to json result file
            bm_results.TimeStamp                = getCurrentTimestamp();
            bm_results.Batchsize                = numSlots;
            bm_results.ScalingTech              = rescaleTech;
            bm_results.SecLevel                 = seclvl;
            bm_results.CompressionLevel         = complvl;
            bm_results.ScaleModSize             = scalemodsize;
            bm_results.FirstModSize             = firstmodsize;
            bm_results.RingDimension            = cryptoContext->GetRingDimension();
            bm_results.MultiplicativeDepth      = depth;
            bm_results.Parties                  = numparties;

            double log2q = log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble());

            bm_results.Log2q = std::isinf(log2q) ? 10000.0 : log2q;
                              

            std::cout << "CKKS scheme is using ring dimension       " << bm_results.RingDimension << std::endl;
            std::cout << "CKKS scheme is using scaling factor       " << bm_results.ScaleModSize << std::endl;
            std::cout << "CKKS scheme is using multiplicative depth " << bm_results.MultiplicativeDepth << std::endl;
            std::cout << "CKKS scheme is using log2(q)              " << bm_results.Log2q << std::endl;

            //Calculate size of the keys
            std::stringstream s1, s2, s3;    
            size_t lengthInBytes;
            Serial::Serialize(cryptoContext, s1, SerType::BINARY);
            std::string str = s1.str();
            bm_results.SizeCryptoContext = sizeof(str[0]) * (str.length() + 1);

            cryptoContext->SerializeEvalMultKey(s2, SerType::BINARY);
            str = s2.str();
            lengthInBytes = sizeof(str[0]) * (str.length() + 1);
            bm_results.SizeEvalMultKey = lengthInBytes / 1024; //Display in kB

            cryptoContext->SerializeEvalSumKey(s3, SerType::BINARY, cryptoContext);
            str = s3.str();
            lengthInBytes = sizeof(str[0]) * (str.length() + 1);
            bm_results.SizeEvalSumKey = lengthInBytes / 1024; //Display in kB
            
        }

        void EncryptData(){
            
            TimeVar t;
            std::cout << "Start of encryption" << std::endl;

            std::vector<double> result;

            for (const auto& [truckId, data] : fleetMap) {
                TIC(t);  //Start timer
                FleetDataCipher& datacipher = CipherInput[truckId];
                Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.cargoWeight); // Step1: Encoding 
                ptxt->SetLength(numSlots); 
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                TIC(t);
                datacipher.cargoWeight = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);  // Step 2: Encrypt  
                bm_results.DurEncryption += TOC_US(t) / 1000.0;
                
                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.co2Emissions);
                ptxt->SetLength(numSlots);
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                datacipher.co2Emissions = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);
                bm_results.DurEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.distanceTravelled);
                ptxt->SetLength(numSlots);
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                datacipher.distanceTravelled = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);
                bm_results.DurEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.driverIDs);
                ptxt->SetLength(numSlots);
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                datacipher.driverIDs = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);
                bm_results.DurEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.emissionFactor);
                ptxt->SetLength(numSlots);
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                datacipher.emissionFactor = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);
                bm_results.DurEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.fuelConsumption);
                ptxt->SetLength(numSlots);
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                datacipher.fuelConsumption = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);
                bm_results.DurEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.locLat);
                ptxt->SetLength(numSlots);
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                datacipher.locLat = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);
                bm_results.DurEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.locLong);
                ptxt->SetLength(numSlots);
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                datacipher.locLong = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);
                bm_results.DurEncryption += TOC_US(t) / 1000.0;

                TIC(t);
                ptxt = cryptoContext->MakeCKKSPackedPlaintext(data.speed);
                ptxt->SetLength(numSlots);
                bm_results.DurEncoding += TOC_US(t) / 1000.0;
                datacipher.speed = cryptoContext->Encrypt(parties[numParties-1].kpShard.publicKey, ptxt);
                bm_results.DurEncryption += TOC_US(t) / 1000.0;

            }

            std::cout << "Size of fleetMap (no. of trucks): " << fleetMap.size() << std::endl;  //contains number of trucks
        

            //substract encoding time from encryption time to get plausible values           
            bm_results.DurEncryption -= bm_results.DurEncoding;  

        }

        /**
         * @brief Takes first element of ciphertext vector and calculates size of data
        */
        void SetDataSize(){
            std::stringstream s;
            Serial::Serialize(CipherInput[0].fuelConsumption, s, SerType::BINARY);
            std::string str = s.str();
            size_t lengthInBytes = sizeof(str[0]) * (str.length() + 1);
            bm_results.SizeData = lengthInBytes / 1024; //Display in kB
        }


         /**
         * @brief inputs a augeschöpften ciphertext and bootrapt    
         * @return gives refreshed Cipher back 
         *      */

        Ciphertext<DCRTPoly> Bootstrap(Ciphertext<DCRTPoly> ct){
            //prepare the ciphertext for threshold multiparty bootstrapping
            auto cadj = cryptoContext->IntMPBootAdjustScale(ct);
            // Leading party (last) generates a Common Random Poly (crp) at max coefficient modulus (QNumPrime).
            // a is sampled at random uniformly from R_{Q}
            auto crp = cryptoContext->IntMPBootRandomElementGen(parties[numParties-1].kpShard.publicKey); // BS preprocessing  Generate a common random polynomial 

            // extract c1 - element-wise
            auto c1 = cadj->Clone();
            c1->GetElements().erase(c1->GetElements().begin());
            std::vector<std::vector<Ciphertext<DCRTPoly>>> sharesPairVec; //

            for(size_t j = 0; j < parties.size(); j++){  //each Party Bootstrap with his Sk  
                std::vector<Ciphertext<DCRTPoly>> sharesPair = cryptoContext->IntMPBootDecrypt(parties[j].kpShard.secretKey, c1, crp); //decrypt 
                sharesPairVec.push_back(sharesPair);
            }

            auto aggregatedSharesPair = cryptoContext->IntMPBootAdd(sharesPairVec);  //aggreat decrypted into on gebootrapped Ciphertext
            return cryptoContext->IntMPBootEncrypt(parties[numParties-1].kpShard.publicKey, aggregatedSharesPair, crp, cadj); //Encrypt  aggregatedSharesPair crp, cadj
        }

        /**
         * @brief Calculates the encrypted result of CO2e (carbon dioxide equivalent) based on encrypted input values.
         */
        void CalcCipherCO2e(){
            TimeVar t, tmult; // Timer variable to measure execution time
            TIC(t); // Start the timer
            std::cout << "\nStart of CO2e calculation" << std::endl; // Print a message indicating the start of the CO2e calculation

            //==============================================================
            // CALCULATION
            //==============================================================

            std::vector<Ciphertext<DCRTPoly>> co2eresultsWoBS;
            bm_results.CO2e_Calc_LvlBefore = CipherInput[0].fuelConsumption->GetLevel();
            std::cout << "\tLevel before CO2e calculation: " << CipherInput[0].fuelConsumption->GetLevel() << std::endl;

            
            for (const auto& [truckId, data] : CipherInput) {
                TIC(tmult);
                auto cm1 = cryptoContext->EvalMult(data.distanceTravelled, data.cargoWeight);
                auto cm2 = cryptoContext->EvalMult(data.emissionFactor, cm1);
                bm_results.CO2e_Calc_DurCalcMult += TOC_US(tmult) / 1000.0;
                cm2      = cryptoContext->EvalSum(cm2, numSlots);
                co2eresultsWoBS.push_back(cm2);
            }
            
            
            std::cout << "\tLevel after CO2e calculation: " << co2eresultsWoBS[0]->GetLevel() << std::endl;
            bm_results.CO2e_Calc_LvlAfter = co2eresultsWoBS[0]->GetLevel();
            bm_results.CO2e_Calc_Dur = TOC_US(t) / 1000.0;

            //==============================================================
            // BOOTSTRAPPING
            //==============================================================
            // some modifications have been made in ckksrns-fhe.cpp in order to get 
            // a console output of bootstrapping timings.
            // The console output is redirected into a stringstream,
            // bootstrapping timings are extracted and then the
            // output is redirected to console again.

            std::cout << "Start with bootstrapping" << std::endl;
            TimeVar t_bs1;
            TIC(t_bs1);  //Start timer for first bootstrapping

            for(size_t i =0; i < co2eresultsWoBS.size(); i++){
                CO2eResult.push_back(Bootstrap(co2eresultsWoBS[i]));                
            }

            bm_results.CO2e_BS_LvlAfter = CO2eResult[0]->GetLevel();
            bm_results.CO2e_BS_Dur = TOC(t_bs1);
            std::cout << "Level after bootstrapping: " << CO2eResult[0]->GetLevel() << std::endl;
            // INTERACTIVE BOOTSTRAPPING ENDS
            
            std::cout << "Start with decryption" << std::endl;
            
            //==============================================================
            // DECRYPTION
            //==============================================================t
            TimeVar t_decr;
            TIC(t_decr);
            std::vector<double> results, resultsbs;


            for(usint i = 0; i < CO2eResult.size(); i++)
            {
                std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec, partialCiphertextVecWoBS;
                //distributed decryption
                //decryption of ciphertext before and after Bootstrapping to analyse precision
                for (usint j=0; j<numParties; j++){
                    if(j < numParties - 1){                        
                        partialCiphertextVecWoBS.push_back(cryptoContext->MultipartyDecryptMain({co2eresultsWoBS[i]}, parties[j].kpShard.secretKey)[0]);
                        partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptMain({CO2eResult[i]}, parties[j].kpShard.secretKey)[0]);
                    }
                    else
                    {
                        partialCiphertextVecWoBS.push_back(cryptoContext->MultipartyDecryptLead({co2eresultsWoBS[i]}, parties[j].kpShard.secretKey)[0]);
                        partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptLead({CO2eResult[i]}, parties[j].kpShard.secretKey)[0]);
                    }
                }
                
                Plaintext resultCO2e, resultCO2eBS;
                cryptoContext->MultipartyDecryptFusion(partialCiphertextVecWoBS, &resultCO2e);
                resultCO2e->SetLength(numSlots);

                cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &resultCO2eBS);
                resultCO2eBS->SetLength(numSlots);

                results.push_back(resultCO2e->GetRealPackedValue()[0]);     //All elements of plaintext are equal therefore its sufficent to read first element
                resultsbs.push_back(resultCO2eBS->GetRealPackedValue()[0]);
            }

            bm_results.DurDecryption += TOC_US(t_decr) / 1000.0;
            
            // Record the duration of the CO2e calculation
            bm_results.CO2e_Dur = TOC_US(t) / 1000.0;
            // Record the precision of the CO2e result
            bm_results.CO2e_Calc_PrecAfter = std::floor(CalculateApproximationError(RawCO2e, results));
            bm_results.CO2e_BS_PrecAfter = std::floor(CalculateApproximationError(RawCO2e, resultsbs));
            bm_results.CO2e_ResExp = vectorToFormattedString(RawCO2e, RawCO2e.size());
            bm_results.CO2e_ResAct = vectorToFormattedString(resultsbs, resultsbs.size());

            // Print the results of the CO2e calculation
            std::cout << "\nResults of CO2e calculation" << std::endl;
            printVector("\tExpected result:\t", RawCO2e, RawCO2e.size());
            printVector("\tActual result:\t\t", resultsbs, resultsbs.size());
            std::cout << "\tPrecision: " << bm_results.CO2e_BS_PrecAfter << " bits" << std::endl;                       
        }

        // void DecryptSingleCipher(std::string name, Ciphertext<DCRTPoly> cipher){
        //     Plaintext pt;

        //     try{
        //         cryptoContext->Decrypt(kpMultiparty.secretKey, cipher, &pt); 

        //         printVector(name, pt->GetRealPackedValue(), numSlots);
        //     }
        //     catch(const std::exception& e)
        //     {
        //         // Handle decryption errors
        //         std::cerr << e.what() << '\n';
        //     }
        // }

        /**
         * @brief Calculates the encrypted squared Pearson correlation coefficient of fuel consumption and cargo weight.
         */


//substract encoding time from encryption time to get plausible values

        void CalcCipherPearsonCorr(){
            TimeVar t, tmean, trsq, tdiv, tsq, t_bs, t_decr; // Timer variable to measure execution time
            TIC(t); // Start the timer
            std::cout << "\nStart of Pearson correlation coefficients calculation" << std::endl; // Print a message indicating the start of the pcor calculation
            std::cout << "Level: " <<  CipherInput[0].fuelConsumption->GetLevel() << std::endl;

            bm_results.PCor_Calc_LvlBefore = CipherInput[0].fuelConsumption->GetLevel();

            //==============================================================
            // CALCULATION
            //==============================================================
            
            for (const auto& [truckId, data] : CipherInput) {
                TIC(tmean);
                // Mean values of fuel consumption and cargo weight
                auto csumfuel       = cryptoContext->EvalSum(data.fuelConsumption, numSlots);
                auto csumweight     = cryptoContext->EvalSum(data.cargoWeight, numSlots);
                auto cmeanfuel      = cryptoContext->EvalMult(0.03125, csumfuel);       // 1/32 = 0,03125
                auto cmeanweight    = cryptoContext->EvalMult(0.03125, csumweight);     // 1/32 = 0,03125
                bm_results.PCor_Calc_DurCalcMean += TOC_US(tmean) / 1000.0;
                // std::cout << "Level after mean calculation: " << cmeanweight->GetLevel() << std::endl;

                // numerator: sum((x_i - x_avg)*(y_i - y_avg))
                auto cxixavg = cryptoContext->EvalSub(data.fuelConsumption, cmeanfuel);
                auto cyiyavg = cryptoContext->EvalSub(data.cargoWeight, cmeanweight);
                auto numerator = cryptoContext->EvalSum(cryptoContext->EvalMult(cxixavg, cyiyavg), numSlots);
                //std::cout << "Level after difference: " << numerator->GetLevel() << std::endl;

                // denominator: sqrt(sum((x_i - x_avg)²) * sum((y_i - y_avg)²))
                TIC(tsq);
                auto denom1 = cryptoContext->EvalSum(cryptoContext->EvalSquare(cxixavg), numSlots);
                auto denom2 = cryptoContext->EvalSum(cryptoContext->EvalSquare(cyiyavg), numSlots);
                auto denom3 = cryptoContext->EvalMult(denom1,denom2);
                bm_results.PCor_Calc_DurCalcSq += TOC_US(tsq) / 1000.0;
                //std::cout << "Level after denom13: " << denom3->GetLevel() << std::endl;
                TIC(trsq);
                double lowerBound = 5e6;  // Chebychev parameter
                double upperBound = 16e6; // Chebychev parameter 
                uint32_t polydeg = 300;  //  Chebychev
                
                /*  Bootstrapping
                * The multiplicative depth detemins the computational capability of the instantiated scheme. It should be set
                * according the following formula: multDepth >= desired_depth + interactive_bootstrapping_depth
                * where,
                *   The desired_depth is the depth of the computation -> 23 
                *       in this case while EvalChebyshevFunction consumes 9 level
                *       The interactive_bootstrapping_depth is either 3 or 4, depending on the ciphertext compression mode: COMPACT vs SLACK (see below)
                *       For this calculation, we need a min. multiplicative depth of 13
                *        9 Level for EvalChebyshevFunction + 4 for interactive bootstrapping.
                * We need to bootstrap two times
                */
                TIC(t_bs);
                denom3 = Bootstrap(denom3); //input BS LVL 2 after BS lvl 0 

                bm_results.PCor_BS_Dur += TOC_US(t_bs) / 1000.0; // add bootstrapping duration in ms
                //std::cout << "Level after first BS: " << denom3->GetLevel() << std::endl;
                auto denom4    = cryptoContext->EvalChebyshevFunction([](double x) -> double { return std::sqrt(x); }, denom3, lowerBound, upperBound, polydeg); // root square consumes 9 + 2
                bm_results.PCor_Calc_DurCalcRSq += TOC_US(trsq) / 1000.0;
                //std::cout << "Level after denom4: " << denom4->GetLevel() << std::endl;
                TIC(t_bs);
                denom4 = Bootstrap(denom4); //actual level: 9
                bm_results.PCor_BS_Dur += TOC_US(t_bs) / 1000.0; // add bootstrapping duration in ms
                //std::cout << "Level after second BS: " << denom4->GetLevel() << std::endl;
                TIC(tdiv);
                auto denominator = cryptoContext->EvalDivide(denom4, std::sqrt(lowerBound), std::sqrt(upperBound), polydeg);// consumes 9 Level
                auto result = cryptoContext->EvalMult(numerator, denominator); // 1 Level  = 10 --> under 14 Decryption possible
                bm_results.PCor_Calc_DurCalcDiv += TOC_US(tdiv) / 1000.0;

                PCorResult.push_back(result);

                // DecryptSingleCipher("Fuel Consumption: ", data.fuelConsumption);
                // DecryptSingleCipher("Cargo Weight: ", data.cargoWeight);
                // DecryptSingleCipher("Sum of Fuel Consumption: ", csumfuel);
                // DecryptSingleCipher("Sum of Cargo Weight: ", csumweight);
                // DecryptSingleCipher("Mean of Fuel Consumption: ", cmeanfuel);
                // DecryptSingleCipher("Mean of Cargo Weight: ", cmeanweight);
                // DecryptSingleCipher("cxixavg: ", cxixavg);
                // DecryptSingleCipher("cyiyavg: ", cyiyavg);
                // DecryptSingleCipher("Numerator: ", numerator);
                // DecryptSingleCipher("denom1: ", denom1);
                // DecryptSingleCipher("denom2: ", denom2);
                // DecryptSingleCipher("Denominator before root square: ", denom3);
                // DecryptSingleCipher("Denominator after root square: ", denom4);
                // DecryptSingleCipher("Denominator (1/x): ", denominator);
                // DecryptSingleCipher("Pearson Correlation Coefficient: ", result);
            }

            bm_results.PCor_Calc_Dur = (TOC_US(t) / 1000.0) - bm_results.PCor_BS_Dur; //separate duration for calculation and bs

            bm_results.PCor_BS_LvlAfter = PCorResult[0]->GetLevel();
            std::cout << "Level after Pearson calculation incl. Bootstrapping " << PCorResult[0]->GetLevel() << std::endl;

            //==============================================================
            // DECRYPTION
            //==============================================================            
            
            // Decrypt the encrypted result
            TIC(t_decr); //start timer for decryption duration
            std::vector<double> results;

            for(usint i = 0; i < PCorResult.size(); i++)
            {
                std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
                //distributed decryption
                for (usint j=0; j<numParties; j++){
                    if(j > 0){    // Backup: < numParties - 1            
                        partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptMain({PCorResult[i]}, parties[j].kpShard.secretKey)[0]);  //Main Partys DEcrypt initial
                    }
                    else
                    {
                        partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptLead({PCorResult[i]}, parties[j].kpShard.secretKey)[0]); // Lead Party finishes Ddecryption
                    }
                }

                Plaintext ptresultBS;

                cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &ptresultBS);  // aggreated into final Plaintext 
                ptresultBS->SetLength(numSlots);

                results.push_back(ptresultBS->GetRealPackedValue()[0]);   //All elements of plaintext are equal therefore its sufficent to read first element
            }
            
            // Record the duration of the Pearson correlation calculation
            bm_results.PCor_Dur = TOC_US(t) / 1000.0;
            bm_results.DurDecryption += TOC_US(t_decr) / 1000.0;
            // Record the precision of the Pearson correlation result
            bm_results.PCor_BS_PrecAfter = std::floor(CalculateApproximationError(RawPCor, results));
            bm_results.PCor_ResExp = vectorToFormattedString(RawPCor, RawPCor.size());
            bm_results.PCor_ResAct = vectorToFormattedString(results, results.size());

            // Print the results of the Pearson correlation 
            std::cout << "\nResults of Pearson correlation" << std::endl;
            printVector("\tExpected result:\t", RawPCor, RawPCor.size());
            printVector("\tActual result:\t\t", results, results.size());
            std::cout << "\tPrecision: " << bm_results.PCor_BS_PrecAfter << " bits" << std::endl;
        }

        /**
         * @brief Calculates the encrypted variance of input values.
         */
        void CalcCipherVar(){
            TimeVar t, tmean, tsub, tsquare; // Timer variable to measure execution time
            TIC(t); // Start the timer

            //==============================================================
            // CALCULATION
            //==============================================================

            std::cout << "\nStart of variance calculation" << std::endl; // Print a message indicating the start of the variance calculation
            std::vector<Ciphertext<DCRTPoly>> varresultsWoBS;
            bm_results.Var_Calc_LvlBefore = CipherInput[0].fuelConsumption->GetLevel();
            std::cout << "\tLevel before variance calculation: " << CipherInput[0].fuelConsumption->GetLevel() << std::endl;

            
            for (const auto& [truckId, data] : CipherInput) {
                // calculate mean value
                TIC(tmean);
                auto csum = cryptoContext->EvalSum(data.fuelConsumption, numSlots);
                auto cmean = cryptoContext->EvalMult(0.03125, csum);   // 1/32 = 0,03125
                bm_results.Var_Calc_DurCalcMean += TOC_US(tmean);

                 // Calculate the squared differences between fuel consumption and the mean
                 TIC(tsub);
                 auto cdiff = cryptoContext->EvalSub(data.fuelConsumption, cmean);
                 bm_results.Var_Calc_DurCalcSub += TOC_US(tsub) / 1000.0;
                 TIC(tsquare);
                 auto csq = cryptoContext->EvalSquare(cdiff);
                 bm_results.Var_Calc_DurCalcSq += TOC_US(tsquare) / 1000.0;

                 // Sum all squared differences and divide it by number of values (32)
                 auto csum2 = cryptoContext->EvalSum(csq, numSlots);
                 auto cresult = cryptoContext->EvalMult(0.03125, csum2);   // 1/32 = 0,03125
                
                varresultsWoBS.push_back(cresult);
            }

            bm_results.Var_Calc_Dur = TOC_US(t) / 1000.0;
            bm_results.Var_Calc_LvlAfter = varresultsWoBS[0]->GetLevel();

            std::cout << "Level after variance calculation: " << varresultsWoBS[0]->GetLevel() << std::endl;

            //==============================================================
            // BOOTSTRAPPING
            //==============================================================
            // some modifications have been made in ckksrns-fhe.cpp in order to get 
            // a console output of bootstrapping timings.
            // The console output is redirected into a stringstream,
            // bootstrapping timings are extracted and then the
            // output is redirected to console again.
            
            TimeVar t_bs1;
            TIC(t_bs1);  //Start timer for first bootstrapping

            std::cout << "Start with bootstrapping" << std::endl;

            for(size_t i =0; i < varresultsWoBS.size(); i++){
                VarResult.push_back(Bootstrap(varresultsWoBS[i]));                
            }
            
            // bm_results.ErrorAfterBS1 = precision;
            bm_results.Var_BS_LvlAfter = VarResult[0]->GetLevel();
            bm_results.Var_BS_Dur = TOC(t_bs1);
            std::cout << "Level after bootstrapping: " << VarResult[0]->GetLevel() << std::endl;

            //==============================================================
            // DECRYPTION
            //==============================================================
            
            // Decrypt the encrypted result
            TimeVar t_decr;
            TIC(t_decr);
            std::vector<double> results, resultsbs;

            for(usint i = 0; i < PCorResult.size(); i++)
            {
                std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec, partialCiphertextVecWoBS;
                //distributed decryption
                //decryption of ciphertext before and after Bootstrapping to analyse precision
                for (usint j=0; j<numParties; j++){
                    if(j < numParties - 1){                
                        partialCiphertextVecWoBS.push_back(cryptoContext->MultipartyDecryptMain({varresultsWoBS[i]}, parties[j].kpShard.secretKey)[0]);
                        partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptMain({VarResult[i]}, parties[j].kpShard.secretKey)[0]);
                    }
                    else
                    {
                        partialCiphertextVecWoBS.push_back(cryptoContext->MultipartyDecryptLead({varresultsWoBS[i]}, parties[j].kpShard.secretKey)[0]);
                        partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptLead({VarResult[i]}, parties[j].kpShard.secretKey)[0]);
                    }
                }

                Plaintext ptresultWoBS, ptresultBS;
                cryptoContext->MultipartyDecryptFusion(partialCiphertextVecWoBS, &ptresultWoBS);
                ptresultWoBS->SetLength(numSlots);

                cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &ptresultBS);
                ptresultBS->SetLength(numSlots);

                results.push_back(ptresultWoBS->GetRealPackedValue()[0]);     //All elements of plaintext are equal therefore its sufficent to read first element
                resultsbs.push_back(ptresultBS->GetRealPackedValue()[0]);
            }
            bm_results.DurDecryption += TOC_US(t_decr) / 1000.0;
            
            // Record the duration of the variance calculation
            bm_results.Var_Dur = TOC_US(t) / 1000.0;
            // Record the precision of the variance result
            bm_results.Var_Calc_PrecAfter = std::floor(CalculateApproximationError(RawVar, results));
            bm_results.Var_BS_PrecAfter = std::floor(CalculateApproximationError(RawVar, resultsbs));
            bm_results.Var_ResExp = vectorToFormattedString(RawVar, RawVar.size());
            bm_results.Var_ResAct = vectorToFormattedString(resultsbs, resultsbs.size());

            // Print the results of the variance calculation
            std::cout << "\nResults of variance calculation" << std::endl;
            printVector("\tExpected result:\t", RawVar, RawVar.size());
            printVector("\tActual result:\t\t", resultsbs, resultsbs.size());
            std::cout << "\tPrecision: " << bm_results.Var_BS_PrecAfter << " bits" << std::endl;
            
            
        }

        /**
         * @brief Calculates the encrypted variance of input values.
         */
        void CalcCipherSDev(){
            TimeVar t, tmean, tsub, tsquare, trsq, t_bs; // Timer variable to measure execution time
            TIC(t); // Start the timer

            //==============================================================
            // CALCULATION
            //==============================================================

            std::cout << "\nStart of standard deviation calculation" << std::endl; // Print a message indicating the start of the standard deviation calculation
            bm_results.SDev_Calc_LvlBefore = CipherInput[0].fuelConsumption->GetLevel();
            std::cout << "\tLevel before standard deviation calculation: " << CipherInput[0].fuelConsumption->GetLevel() << std::endl;
            
            for (const auto& [truckId, data] : CipherInput) {
                // calculate mean value
                TIC(tmean);
                auto csum = cryptoContext->EvalSum(data.fuelConsumption, numSlots);
                auto cmean = cryptoContext->EvalMult(0.03125, csum);   // 1/32 = 0,03125
                bm_results.SDev_Calc_DurCalcMean += TOC_US(tmean) / 1000.0;

                // Calculate the squared differences between fuel consumption and the mean
                TIC(tsub);
                auto cdiff = cryptoContext->EvalSub(data.fuelConsumption, cmean);
                bm_results.SDev_Calc_DurCalcSub += TOC_US(tsub) / 1000.0;
                TIC(tsquare);
                auto csq = cryptoContext->EvalSquare(cdiff);
                // Sum all squared differences and divide it by number of values (32)
                auto csum2 = cryptoContext->EvalSum(csq, numSlots);
                auto cresult = cryptoContext->EvalMult(0.03125, csum2);   // 1/32 = 0,03125
                bm_results.SDev_Calc_DurCalcSq += TOC_US(tsquare) / 1000.0;

                // Bootstrapping before computationally intense operation of root square
                // Reduces level from 2 to 0
                TIC(t_bs);
                cresult = Bootstrap(cresult);
                bm_results.SDev_BS_Dur += TOC_US(t_bs) / 1000.0;
                TIC(trsq);         

                cresult  = cryptoContext->EvalChebyshevFunction([](double x) -> double { return std::sqrt(x); }, cresult, 60, 130, 150); // root square
                bm_results.SDev_Calc_DurCalcRSq += TOC_US(trsq) / 1000.0;
                
                SDevResult.push_back(cresult);
            }

            bm_results.SDev_Calc_Dur = TOC_US(t) / 1000.0 - bm_results.SDev_BS_Dur; // separate calculation time and bootstrapping duration
            bm_results.SDev_BS_LvlAfter = SDevResult[0]->GetLevel();


            //==============================================================
            // DECRYPTION
            //==============================================================

            // Decrypt the encrypted result
            TimeVar t_decr;
            TIC(t_decr);
            std::vector<double> resultsbs;

            for(usint i = 0; i < SDevResult.size(); i++)
            {
                std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;


                //distributed decryption
                //decryption of ciphertext before and after Bootstrapping to analyse precision

                for (usint j=0; j<numParties; j++){
                    if(j < numParties - 1){                
                        partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptMain({SDevResult[i]}, parties[j].kpShard.secretKey)[0]); //“Partial” decryption computed by all parties except for the lead one
                    }
                    else
                    {
                        partialCiphertextVec.push_back(cryptoContext->MultipartyDecryptLead({SDevResult[i]}, parties[j].kpShard.secretKey)[0]); // decryption of lead One 

                    }
                }

                Plaintext ptresultBS;


                cryptoContext->MultipartyDecryptFusion(partialCiphertextVec, &ptresultBS);
                ptresultBS->SetLength(numSlots);

                resultsbs.push_back(ptresultBS->GetRealPackedValue()[0]);
            }
            bm_results.DurDecryption += TOC_US(t_decr) / 1000.0;
            // Record the duration of the standard deviation calculation
            bm_results.SDev_Dur = TOC_US(t) / 1000.0;
            // Record the precision of the standard deviation result
            bm_results.SDev_BS_PrecAfter = std::floor(CalculateApproximationError(RawSDev, resultsbs));
            bm_results.SDev_ResExp = vectorToFormattedString(RawSDev, RawSDev.size());
            bm_results.SDev_ResAct = vectorToFormattedString(resultsbs, resultsbs.size());

            // Print the results of the standard deviation calculation
            std::cout << "\nResults of standard deviation calculation" << std::endl;
            printVector("\tExpected result:\t", RawSDev, RawSDev.size());
            printVector("\tActual result:\t\t", resultsbs, resultsbs.size());
            std::cout << "\tPrecision: " << bm_results.SDev_BS_PrecAfter << " bits" << std::endl;
        }
            

        /**
         * @brief Calculates the throughput of several KPIs in kb/s
        */
        void CalculateThroughput(){
            
            int length = CipherInput.size();

            // Encryption throughput: amount of encrypted datasets multiplied with data size divided by duration (in seconds)
            bm_results.ThroughputEncryption = (bm_results.SizeData * length) / (static_cast<double>(bm_results.DurEncryption) / 1000);

            // Encryption throughput: amount of result ciphertexts (CO2e, mean, var) multiplied with data size divided by duration (in seconds)
            bm_results.ThroughputDecryption = (bm_results.SizeData * 4) / (static_cast<double>(bm_results.DurDecryption) / 1000);

            bm_results.CO2e_BS_Throughput = (bm_results.SizeData / static_cast<double>(bm_results.CO2e_BS_Dur) / 1000);
            bm_results.PCor_BS_Throughput = (bm_results.SizeData / static_cast<double>(bm_results.PCor_BS_Dur) / 1000);
            bm_results.Var_BS_Throughput  = (bm_results.SizeData / static_cast<double>(bm_results.Var_BS_Dur) / 1000);
            bm_results.SDev_BS_Throughput = (bm_results.SizeData / static_cast<double>(bm_results.SDev_BS_Dur) / 1000);

        }

        /**
         * @brief Handles json file. Creating a new one if file doesn't exist.
         * Otherwise, it appends the current result to the file.
         */
        void WriteJSON(double OverallDuration, std::string filename){
            //Add overall duration to result file
            bm_results.DurOverall = OverallDuration;
            std::cout << "\nOverall duration: " << OverallDuration << " ms" << std::endl;

            Json::Value root;
            std::ifstream inputFile(filename);
            if (inputFile.is_open()) {
                inputFile >> root;
                inputFile.close();
            } else {
                root = Json::Value(Json::arrayValue); 
                std::cout << "No JSON file fount. Creating a new one" << std::endl;
            }

            // new json object with current results
            Json::Value newResult;
            newResult["Batchsize [-]"]                  = bm_results.Batchsize;

            newResult["CO2e_Dur [ms]"]                   = bm_results.CO2e_Dur;
            newResult["CO2e_BS_Dur [ms]"]                = bm_results.CO2e_BS_Dur;
            newResult["CO2e_BS_LvlAfter [-]"]           = bm_results.CO2e_BS_LvlAfter;
            newResult["CO2e_BS_PrecAfter [bit]"]          = bm_results.CO2e_BS_PrecAfter;
            newResult["CO2e_Calc_Dur [ms]"]              = bm_results.CO2e_Calc_Dur;
            newResult["CO2e_Calc_DurCalcMult [ms]"]      = bm_results.CO2e_Calc_DurCalcMult;
            newResult["CO2e_Calc_LvlAfter [-]"]         = bm_results.CO2e_Calc_LvlAfter;
            newResult["CO2e_Calc_LvlBefore [-]"]        = bm_results.CO2e_Calc_LvlBefore;
            newResult["CO2e_Calc_PrecAfter [bit]"]        = bm_results.CO2e_Calc_PrecAfter;
            newResult["CO2e_ResAct"]                = bm_results.CO2e_ResAct;
            newResult["CO2e_ResExp"]                = bm_results.CO2e_ResExp;

            newResult["Comment"]                    = bm_results.Comment;

            newResult["DurDecryption [ms]"]              = bm_results.DurDecryption;
            newResult["DurOverall [ms]"]                 = bm_results.DurOverall;
            newResult["DurEncoding [ms]"]                = bm_results.DurEncoding;
            newResult["DurEncryption [ms]"]              = bm_results.DurEncryption;
            newResult["DurKeyGen [ms]"]                  = bm_results.DurKeyGen;

            newResult["FirstModSize [bit]"]               = bm_results.FirstModSize;
            newResult["Log2(q) [-]"]               = bm_results.Log2q;
            newResult["Parties [-]"]               = bm_results.Parties;
            newResult["MultiplicativeDepth [-]"]        = bm_results.MultiplicativeDepth;

            newResult["PCor_Dur [ms]"]                   = bm_results.PCor_Dur;
            newResult["PCor_BS_LvlAfter [-]"]           = bm_results.PCor_BS_LvlAfter;
            newResult["PCor_BS_PrecAfter [bit]"]          = bm_results.PCor_BS_PrecAfter;
            newResult["PCor_BS_Dur [ms]"]                = bm_results.PCor_BS_Dur;
            newResult["PCor_Calc_Dur [ms]"]              = bm_results.PCor_Calc_Dur;            
            newResult["PCor_Calc_DurCalcMean [ms]"]      = bm_results.PCor_Calc_DurCalcMean;
            newResult["PCor_Calc_DurCalcSq [ms]"]        = bm_results.PCor_Calc_DurCalcSq;
            newResult["PCor_Calc_DurCalcDiv [ms]"]       = bm_results.PCor_Calc_DurCalcDiv;
            newResult["PCor_Calc_DurCalcRSq [ms]"]       = bm_results.PCor_Calc_DurCalcRSq;
            newResult["Pcor_ResAct"]                = bm_results.PCor_ResAct;
            newResult["PCor_ResExp"]                = bm_results.PCor_ResExp;
           
            newResult["RingDimension [bit]"]              = bm_results.RingDimension;
            newResult["ScaleModSize [bit]"]               = bm_results.ScaleModSize;
            newResult["ScalingTechnique [-]"]           = bm_results.ScalingTech;
            newResult["SecurityLevel [-]"]              = bm_results.SecLevel;
            newResult["CompressionLevel [-]"]           = bm_results.CompressionLevel;
           
            newResult["SDev_Dur [ms]"]                   = bm_results.SDev_Dur;
            newResult["SDev_BS_LvlAfter [-]"]           = bm_results.SDev_BS_LvlAfter;
            newResult["SDev_BS_PrecAfter [bit]"]          = bm_results.SDev_BS_PrecAfter;
            newResult["SDev_BS_Dur [ms]"]                = bm_results.SDev_BS_Dur;
            newResult["SDev_Calc_Dur [ms]"]              = bm_results.SDev_Calc_Dur;
            newResult["SDev_Calc_DurCalcMean [ms]"]      = bm_results.SDev_Calc_DurCalcMean;
            newResult["SDev_Calc_DurCalcSq [ms]"]        = bm_results.SDev_Calc_DurCalcSq;            
            newResult["SDev_Calc_DurCalcRSq [ms]"]       = bm_results.SDev_Calc_DurCalcRSq;
            newResult["SDev_Calc_DurCalcSub [ms]"]       = bm_results.SDev_Calc_DurCalcSub;
            newResult["SDev_ResAct"]                = bm_results.SDev_ResAct;
            newResult["SDev_ResExp"]                = bm_results.SDev_ResExp;
            newResult["SizeCryptoContext [kB]"]          = bm_results.SizeCryptoContext;
            newResult["SizeData [kB]"]                   = bm_results.SizeData;
            newResult["SizeEvalMultKey [kB]"]            = bm_results.SizeEvalMultKey;
            newResult["SizeEvalSumKey [kB]"]             = bm_results.SizeEvalSumKey;

            newResult["ThroughputDecryption [kB/s]"]       = bm_results.ThroughputDecryption;
            newResult["ThroughputEncryption [kB/s]"]       = bm_results.ThroughputEncryption;

            newResult["Var_BS_LvlAfter [-]"]            = bm_results.Var_BS_LvlAfter;
            newResult["Var_BS_PrecAfter [-]"]           = bm_results.Var_BS_PrecAfter;            
            newResult["Var_Dur [ms]"]                    = bm_results.Var_Dur;            
            newResult["Var_BS_Dur [ms]"]                 = bm_results.Var_BS_Dur;                        
            newResult["Var_Calc_Dur [ms]"]               = bm_results.Var_Calc_Dur;
            newResult["Var_Calc_DurCalcMean [ms]"]       = bm_results.Var_Calc_DurCalcMean;
            newResult["Var_Calc_DurCalcSq [ms]"]         = bm_results.Var_Calc_DurCalcSq;
            newResult["Var_Calc_DurCalcSub [ms]"]        = bm_results.Var_Calc_DurCalcSub;
            newResult["Var_Calc_LvlAfter [ms]"]          = bm_results.Var_Calc_LvlAfter;
            newResult["Var_ResAct"]                 = bm_results.Var_ResAct;
            newResult["Var_ResExp"]                 = bm_results.Var_ResExp;

            newResult["TimeStamp"]                  = bm_results.TimeStamp;


            root.append(newResult);

            // write json file
            std::ofstream outputFile(filename);
            if (outputFile.is_open()) {
                outputFile << root;
                outputFile.close();
                std::cout << "Results appended to JSON file." << std::endl;
            } else {
                std::cerr << "Error while writing JSON file." << std::endl;
            }
        }
        // Without this function mem Leak is given. 
        void ClearFHE(){
            cryptoContext->ClearEvalMultKeys();
            cryptoContext->ClearEvalAutomorphismKeys();
            lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
        }
};

void Benchmark(const std::string& filename, int repetitions, ScalingTechnique rescaletech, SecurityLevel seclvl, int numparties, int scalemodsize, int firstmodsize, COMPRESSION_LEVEL complvl, int deslvl){
    
    for(int i=0; i < repetitions; i++){ 
        TimeVar t;

        std::cout << "\n====== Benchmark (" << rescaletech << "/" << seclvl << "/" << numparties << "/" << scalemodsize << "/" << firstmodsize << "/" << complvl << "/" << deslvl << ") =====\n" << std::endl;
        std::cout << "       Repetition " << i+1 << "/" << repetitions << std::endl;
        TIC(t);
        
        try{            
            FHEBenchmark bm(rescaletech, seclvl, numparties, scalemodsize, firstmodsize, complvl, deslvl);
            bm.EncryptData();
            bm.SetDataSize(); //Serialize 
            bm.CalcCipherCO2e();   // Calculations for Use-Case 
            bm.CalcCipherPearsonCorr();
            bm.CalcCipherVar();
            bm.CalcCipherSDev();   // End Calculations for Use-Case 
            bm.CalculateThroughput();   // This is for Chapter Green-IT 
            bm.WriteJSON(TOC(t), filename);
            bm.ClearFHE();
        }
        catch(const std::exception& e)
        {
            std::cerr << e.what() << '\n';
            break;
        }
        
    }

}

int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <Filename.json> <Repetitions>" << std::endl;
        return 1;
    }

    // save parameters to variabels
    std::string Filename = argv[1];
    int Repetitions = std::atoi(argv[2]); // std::atoi casts string to int

    // check if repetions is a positive integer
    if (Repetitions <= 0) {
        std::cerr << "Reptitions must be a positive integer" << std::endl;
        return 1;
    }


    ////////////////////////////////////////////////////////////////
    // Read fleet data from json file and make it available as global variable
    ////////////////////////////////////////////////////////////////
    // 
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::ifstream file("FleetData.json");
    std::string errors;

    if (!Json::parseFromStream(builder, file, &root, &errors)) {
        std::cout << "Error while parsing json file: " << errors << std::endl;
    }
    /////////////////////////////////////////////////////////////
    // Extract Data 
    /////////////////////////////////////////////////////////////
    // 
    for (const auto& entry : root) {
        int truckId = entry["TruckID"].asInt();
        FleetData& data = fleetMap[truckId]; 

        data.driverIDs.push_back(entry["DriverID"].asDouble());
        data.locLat.push_back(entry["LocLat"].asDouble());
        data.locLong.push_back(entry["LocLong"].asDouble());
        data.distanceTravelled.push_back(entry["DistanceTravelled"].asDouble());
        data.co2Emissions.push_back(entry["CO2Emissions"].asDouble());
        data.emissionFactor.push_back(entry["EmssionFactor"].asDouble());
        data.speed.push_back(entry["Speed"].asDouble());
        data.fuelConsumption.push_back(entry["FuelConsumption"].asDouble());
        data.cargoWeight.push_back(entry["CargoWeight"].asDouble());
    }

    ////////////////////////////////////////////////////////////////
    // BENCHMARKING LOGIC FOR INPUT PARAMETRS 
    ////////////////////////////////////////////////////////////////

    TimeVar t;
    TIC(t);  //Start timer

    int i = 1;

    for (ScalingTechnique st :{ScalingTechnique::FIXEDAUTO, ScalingTechnique::FLEXIBLEAUTO, ScalingTechnique::FLEXIBLEAUTOEXT}) { // Rescale technique
        for (SecurityLevel sl : {SecurityLevel::HEStd_128_classic, SecurityLevel::HEStd_192_classic, SecurityLevel::HEStd_256_classic}) {     // security Level
            for (int p : {3,6}){    // No of parties, why not 2
                for (auto sf : {std::make_pair(40, 45), std::make_pair(50, 55), std::make_pair(59, 60)}) { //ScaleModSize and FirstModSize:
                    for (COMPRESSION_LEVEL cl : {COMPRESSION_LEVEL::COMPACT, COMPRESSION_LEVEL::SLACK}) { // compression level

                        std::cout << "##############################" << std::endl;
                        std::cout << "  Benchmark no " << i++ << "/" << 108 << std::endl;
                        std::cout << "##############################" << std::endl;
                        Benchmark(Filename, Repetitions, st, sl, p, sf.first, sf.second, cl, 14);  //Mult Depth 14  

                    }
                }
            }
        }
    }

    int seconds = TOC(t) / 1000;            // ms --> s
    int hours = seconds / 3600;             // s --> h
    int remainingSeconds = seconds % 3600;  // remaining secods after conversion into hours
    int minutes = remainingSeconds / 60;    // s --> min

    std::cout << "\n Benchmarking completed in " << hours << " hours and " << minutes << " minutes." << std::endl;
        
}
