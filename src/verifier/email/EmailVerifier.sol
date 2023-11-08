// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "../../libraries/LibRsa.sol";
import "../../libraries/LibBytes.sol";
import "../../libraries/LibBase64.sol";
import "./DkimKeys.sol";

import "@openzeppelin/contracts/utils/Address.sol";

contract EmailVerifier is DkimKeys {
    using LibBytes for bytes;
    using Address for address;

    error InvalidEncodings(bytes1 _encodings);
    error InvalidEmailVerifyType(uint8 _emailVerifyType);
    error GetEmailHashByZKRevert(bytes _reason);

    bytes1 public constant AtSignBytes1 = 0x40;
    bytes1 public constant DotSignBytes1 = 0x2e;

    enum DkimParamsIndex {
        emailType,
        subjectIndex,
        subjectRightIndex,
        fromIndex,
        fromLeftIndex,
        fromRightIndex,
        dkimHeaderIndex,
        selectorIndex,
        selectorRightIndex,
        sdidIndex,
        sdidRightIndex
    }
    uint256 constant DkimParamsIndexNum = 11;

    uint256 private constant VERIFY_BY_ORI_EMAIL = 0;
    uint256 private constant VERIFY_BY_ZK = 1;

    constructor() {}

    function _getSubject(
        uint256 _startIndex,
        bytes calldata _data,
        bytes calldata _emailHeader
    ) internal pure returns (bytes memory decodedSubject) {
        bytes calldata subjectHeader = _getRawSubject(
            _startIndex,
            _data,
            _emailHeader
        );
        decodedSubject = _parseSubjectHeader(subjectHeader);
    }

    function _getRawSubject(
        uint256 _startIndex,
        bytes calldata _data,
        bytes calldata _emailHeader
    ) internal pure returns (bytes calldata rawSubject) {
        uint32 subjectIndex;
        (subjectIndex, ) = _data.cReadUint32(
            _startIndex + uint256(DkimParamsIndex.subjectIndex) * 4
        );
        uint32 subjectRightIndex;
        (subjectRightIndex, ) = _data.cReadUint32(
            _startIndex + uint256(DkimParamsIndex.subjectRightIndex) * 4
        );
        // see https://datatracker.ietf.org/doc/html/rfc5322#section-2.2
        if (subjectIndex != 0) {
            require(
                _emailHeader.mcReadBytesN(subjectIndex - 2, 10) ==
                    bytes32("\r\nsubject:"),
                "FE"
            );
        } else {
            require(
                _emailHeader.mcReadBytesN(subjectIndex, 8) ==
                    bytes32("subject:"),
                "FE"
            );
        }
        // see https://datatracker.ietf.org/doc/html/rfc5322#section-2.2
        for (uint256 i = subjectIndex + 8; i < subjectRightIndex; i++) {
            require(_emailHeader[i] != "\n", "NE");
        }

        rawSubject = _emailHeader[subjectIndex + 8:subjectRightIndex];
    }

    function _getEmailFromIndexes(
        uint256 _startIndex,
        bytes calldata _data,
        bytes calldata _emailHeader
    )
        internal
        pure
        returns (uint32 fromIndex, uint32 fromLeftIndex, uint32 fromRightIndex)
    {
        (fromIndex, ) = _data.cReadUint32(
            _startIndex + uint256(DkimParamsIndex.fromIndex) * 4
        );
        (fromLeftIndex, ) = _data.cReadUint32(
            _startIndex + uint256(DkimParamsIndex.fromLeftIndex) * 4
        );
        (fromRightIndex, ) = _data.cReadUint32(
            _startIndex + uint256(DkimParamsIndex.fromRightIndex) * 4
        );
        if (fromIndex != 0) {
            require(
                _emailHeader.mcReadBytesN(fromIndex - 2, 7) ==
                    bytes32("\r\nfrom:"),
                "FE"
            );
        } else {
            require(
                _emailHeader.mcReadBytesN(fromIndex, 5) == bytes32("from:"),
                "FE"
            );
        }
        // see https://www.rfc-editor.org/rfc/rfc2822#section-3.4.1
        require(
            fromIndex + 4 < fromLeftIndex && fromLeftIndex < fromRightIndex,
            "LE"
        );
        if (
            _emailHeader[fromLeftIndex - 1] == "<" &&
            _emailHeader[fromRightIndex + 1] == ">"
        ) {
            for (uint256 i = fromLeftIndex - 1; i > fromIndex + 4; i--) {
                require(_emailHeader[i] != "\n", "NE");
            }
        } else {
            require(fromLeftIndex == fromIndex + 5, "AE");
        }
    }

    function _getEmailFrom(
        bytes32 _pepper,
        uint256 _startIndex,
        bytes calldata _data,
        bytes calldata _emailHeader
    ) internal pure returns (bytes32 emailHash) {
        (, uint32 fromLeftIndex, uint32 fromRightIndex) = _getEmailFromIndexes(
            _startIndex,
            _data,
            _emailHeader
        );

        emailHash = sha256(
            abi.encodePacked(
                _emailHeader[fromLeftIndex:fromRightIndex + 1],
                _pepper
            )
        );
    }

    function _getDkimInfo(
        bytes calldata _data,
        uint256 _startIndex,
        bytes calldata _emailHeader
    ) internal pure returns (bytes32 selector, bytes32 sdid) {
        uint32 dkimHeaderIndex;
        (dkimHeaderIndex, ) = _data.cReadUint32(
            _startIndex + uint256(DkimParamsIndex.dkimHeaderIndex) * 4
        );
        require(
            _emailHeader.mcReadBytesN(dkimHeaderIndex - 2, 17) ==
                bytes32("\r\ndkim-signature:"),
            "DE"
        );

        {
            uint256 selectorIndex;
            (selectorIndex, ) = _data.cReadUint32(
                _startIndex + uint256(DkimParamsIndex.selectorIndex) * 4
            );
            uint256 selectorRightIndex;
            (selectorRightIndex, ) = _data.cReadUint32(
                _startIndex + uint256(DkimParamsIndex.selectorRightIndex) * 4
            );
            require(selectorIndex > dkimHeaderIndex, "DHE");
            require(
                _emailHeader.mcReadBytesN(selectorIndex - 4, 4) ==
                    bytes32("; s="),
                "DSE"
            );
            selector = bytes32(_emailHeader[selectorIndex:selectorRightIndex]);
        }

        {
            uint256 sdidIndex;
            (sdidIndex, ) = _data.cReadUint32(
                _startIndex + uint256(DkimParamsIndex.sdidIndex) * 4
            );
            uint256 sdidRightIndex;
            (sdidRightIndex, ) = _data.cReadUint32(
                _startIndex + uint256(DkimParamsIndex.sdidRightIndex) * 4
            );
            require(sdidIndex > dkimHeaderIndex, "DHE");

            require(
                _emailHeader.mcReadBytesN(sdidIndex - 4, 4) == bytes32("; d="),
                "DDE"
            );
            sdid = _emailHeader.mcReadBytesN(
                sdidIndex,
                sdidRightIndex - sdidIndex
            );
        }
    }

    function _verifyDkimSignature(
        uint256 _startIndex,
        bytes calldata _data,
        bytes calldata _emailHeader,
        bytes calldata _dkimSig
    ) internal view returns (bool ret) {
        bytes32 selector;
        bytes32 sdid;
        (selector, sdid) = _getDkimInfo(_data, _startIndex, _emailHeader);

        bytes memory n = getDKIMKey(abi.encodePacked(selector, sdid));
        require(n.length > 0, "zero");
        ret = LibRsa.rsapkcs1Verify(
            sha256(_emailHeader),
            n,
            hex"010001",
            _dkimSig
        );
    }

    function dkimVerify(
        uint256 _startIndex,
        bytes calldata _data
    )
        external
        view
        returns (
            bool ret,
            bytes32 emailHash,
            bytes memory subject,
            uint256 endIndex
        )
    {
        uint8 emailVerifyType = _data.mcReadUint8(_startIndex);
        ++_startIndex;

        bytes calldata emailHeader;
        bytes calldata dkimSig;
        {
            endIndex = DkimParamsIndexNum * 4 + _startIndex;
            uint32 len;
            (len, endIndex) = _data.cReadUint32(endIndex);
            emailHeader = _data[endIndex:endIndex + len];
            endIndex += len;
            (len, endIndex) = _data.cReadUint32(endIndex);
            dkimSig = _data[endIndex:endIndex + len];
            endIndex += len;
        }

        {
            subject = _getSubject(_startIndex, _data, emailHeader);
        }
        if (emailVerifyType == VERIFY_BY_ORI_EMAIL) {
            bytes32 pepper = _data.mcReadBytes32(endIndex);
            endIndex += 32;
            emailHash = _getEmailFrom(pepper, _startIndex, _data, emailHeader);
            ret = _verifyDkimSignature(
                _startIndex,
                _data,
                emailHeader,
                dkimSig
            );
        } else {
            revert InvalidEmailVerifyType(emailVerifyType);
        }
    }

    function removeDotForEmailFrom(
        bytes calldata _emailFrom,
        uint256 _atSignIndex
    ) internal pure returns (bytes memory fromRet) {
        uint256 leftIndex;
        for (uint256 index; index < _atSignIndex; index++) {
            fromRet = leftIndex == 0
                ? _emailFrom[leftIndex:index]
                : bytes.concat(fromRet, _emailFrom[leftIndex:index]);
            leftIndex = index;
        }
        if (leftIndex == 0) {
            fromRet = _emailFrom;
        } else {
            bytes.concat(fromRet, _emailFrom[_atSignIndex:_emailFrom.length]);
        }
    }

    function _parseSubjectHeader(
        bytes calldata _subjectHeader
    ) internal pure returns (bytes memory ret) {
        uint256 index;
        while (index < _subjectHeader.length - 1) {
            if (_subjectHeader[index] == " ") {
                ++index;
                continue;
            }

            uint256 startIndex;
            uint256 endIndex;

            if (_subjectHeader[index + 1] == "?") {
                require(
                    _subjectHeader[index] == "=",
                    "_parseSubjectHeader: INVALID_HEADER"
                );
                bytes1 encodings;
                index += 2;
                while (index < _subjectHeader.length - 1) {
                    if (
                        _subjectHeader[index] == "?" &&
                        _subjectHeader[index + 2] == "?"
                    ) {
                        encodings = _subjectHeader[index + 1];
                        index += 3;
                        startIndex = index;
                        break;
                    }
                    ++index;
                }
                require(
                    startIndex != 0,
                    "_parseSubjectHeader: INVALID_START_HEADER"
                );
                while (index < _subjectHeader.length - 1) {
                    if (_subjectHeader[index + 1] == "?") {
                        require(
                            _subjectHeader[index + 2] == "=",
                            "_parseSubjectHeader: INVALID_HEADER"
                        );
                        endIndex = index + 1;
                        index += 2;
                        break;
                    }
                    ++index;
                }
                require(
                    endIndex != 0,
                    "_parseSubjectHeader: INVALID_END_HEADER"
                );
                if (encodings == "B" || encodings == "b") {
                    ret = bytes.concat(
                        ret,
                        LibBase64.decode(_subjectHeader[startIndex:endIndex])
                    );
                    continue;
                }
                if (encodings == "Q" || encodings == "q") {
                    ret = bytes.concat(
                        ret,
                        _subjectHeader[startIndex:endIndex]
                    );
                    continue;
                }
                revert InvalidEncodings(encodings);
            }

            startIndex = index;
            while (index < _subjectHeader.length - 1) {
                if (_subjectHeader[index + 1] == " ") {
                    endIndex = index;
                    index += 2;
                }
                ++index;
            }
            endIndex = endIndex == 0 ? _subjectHeader.length : endIndex;
            ret = bytes.concat(ret, _subjectHeader[startIndex:endIndex]);
        }
    }
}
